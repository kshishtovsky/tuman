"""Тесты эмулятора: парсеры на реальных байтах + R1–R5.

Запуск (без root, без Docker): python3 -m unittest -v test_rules.py
"""
from __future__ import annotations

import contextlib
import io
import os
import socket
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dpi import engine, parsers, rules  # noqa: E402

CLI, SRV = "10.10.0.1", "10.20.0.1"

# Эталон Chrome (JA3 из публичных списков, TLS1.3 + GREASE в трафике).
CHROME_JA3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-"
              "156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,"
              "29-23-24,0")
CHROME_HASH = "cd08e31494f9531f560d64c695473da9"
OPENSSL_HASH = "37f7d09ced1a845dc48872abc1a29d7b"  # OpenSSL 3.x default (см. rules.BROWSER_JA3)

CHROME_CIPHERS = [0x0A0A, 4865, 4866, 4867, 49195, 49199, 49196, 49200,
                  52393, 52392, 49171, 49172, 156, 157, 47, 53]
CHROME_EXTS = [0x0A0A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21]
CHROME_CURVES = [0x1A1A, 29, 23, 24]


def _ext(etype, data):
    return struct.pack("!HH", etype, len(data)) + data


def _ext_data(etype, sni, curves, formats):
    if etype == 0:
        host = sni.encode()
        name = struct.pack("!BH", 0, len(host)) + host
        return struct.pack("!H", len(name)) + name
    if etype == 10:
        body = b"".join(struct.pack("!H", c) for c in curves)
        return struct.pack("!H", len(body)) + body
    if etype == 11:
        return bytes([len(formats)]) + formats
    if etype == 51:  # key_share: одна x25519-группа
        share = struct.pack("!HH", 29, 32) + b"\x07" * 32
        return struct.pack("!H", len(share)) + share
    if etype == 43:  # supported_versions
        return b"\x04\x03\x04\x03\x03"
    if etype == 13:  # signature_algorithms
        return b"\x00\x04\x08\x04\x04\x03"
    return b"\x00\x00"


def build_client_hello(sni="example.com", ciphers=None, exts=None, curves=None,
                       formats=b"\x00", sid=b"\x20" * 32):
    ciphers = CHROME_CIPHERS if ciphers is None else ciphers
    exts = CHROME_EXTS if exts is None else exts
    curves = CHROME_CURVES if curves is None else curves

    body = struct.pack("!H", 0x0303) + b"\x33" * 32            # legacy_version + random
    body += bytes([len(sid)]) + sid
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body += struct.pack("!H", len(cs)) + cs
    body += b"\x01\x00"                                        # 1 compression method
    ext = b"".join(_ext(t, _ext_data(t, sni, curves, formats)) for t in exts)
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, 0x0301, len(hs)) + hs


def tls_record(ctype, body):
    return struct.pack("!BHH", ctype, 0x0303, len(body)) + body


def appdata(n):
    return tls_record(23, b"\xaa" * n)


def ipv4(proto, src, dst, payload, flags=0x4000):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, flags, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def frame_tcp(src, dst, sport, dport, payload, flags=0x18):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 0xFFFF, 0, 0)
    return ipv4(6, src, dst, tcp + payload)


def frame_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ipv4(17, src, dst, udp)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))  # linktype RAW
        for ts, fr in frames:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)))
            f.write(fr)


def must(decision, what="правило"):
    if decision is None:
        raise AssertionError(f"{what} не сработало")
    return decision


def ssl_client_hello(host):
    """Реальный ClientHello от OpenSSL через MemoryBIO — байты как в проводе."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ib, ob = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(ib, ob, server_side=False, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return ob.read()


class TestParsers(unittest.TestCase):
    def test_ipv4_tcp_with_eth_padding(self):
        pkt = frame_tcp(CLI, SRV, 40000, 443, b"hello") + b"\x00" * 12  # padding в кадре
        ip = parsers.parse_ipv4(pkt)
        self.assertEqual((ip.src, ip.dst, ip.proto), (CLI, SRV, 6))
        tcp = parsers.parse_tcp(ip.payload)
        self.assertEqual((tcp.sport, tcp.dport, tcp.payload), (40000, 443, b"hello"))

    def test_ipv4_udp_and_non_ip(self):
        udp = parsers.parse_udp(parsers.parse_ipv4(frame_udp(CLI, SRV, 5555, 443, b"x" * 5)).payload)
        self.assertEqual((udp.sport, udp.payload), (5555, b"x" * 5))
        with self.assertRaises(parsers.ParseError):
            parsers.parse_ipv4(b"\x45" * 10)         # короче заголовка
        with self.assertRaises(parsers.ParseError):
            parsers.parse_ipv4(b"\x65" + b"\x00" * 30)  # IPv6

    def test_tls_record_sizes(self):
        buf = tls_record(22, b"a" * 10) + appdata(1400) + tls_record(23, b"b" * 5)[:4]
        recs = parsers.tls_records(buf)              # неполный хвост отбрасывается
        self.assertEqual([(r.ctype, r.size) for r in recs], [(22, 10), (23, 1400)])

    def test_chrome_client_hello_ja3(self):
        ch = parsers.parse_client_hello(build_client_hello("tuman.example"))
        self.assertEqual(ch.sni, "tuman.example")
        self.assertEqual(ch.version, 771)
        self.assertIn(0, ch.extensions)
        self.assertIn(51, ch.extensions)
        self.assertEqual(parsers.ja3_string(ch), CHROME_JA3)
        self.assertEqual(parsers.ja3_hash(ch), CHROME_HASH)
        self.assertIn(CHROME_HASH, rules.BROWSER_JA3)

    def test_grease_stripped_from_ja3(self):
        ch = parsers.parse_client_hello(build_client_hello())
        ja3 = parsers.ja3_string(ch)
        for grease in ("2570", "6682", "1025"):      # 0x0a0a, 0x1a1a, 0x0401-подобные
            self.assertNotIn(grease, ja3.split(",")[1])

    def test_real_openssl_client_hello(self):
        a = parsers.parse_client_hello(ssl_client_hello("example.com"))
        b = parsers.parse_client_hello(ssl_client_hello("other.example"))
        self.assertEqual(a.sni, "example.com")
        self.assertEqual(b.sni, "other.example")
        self.assertEqual(a.version, 771)
        self.assertTrue(a.ciphers)
        # JA3 не зависит от SNI, только от набора параметров
        self.assertEqual(parsers.ja3_hash(a), parsers.ja3_hash(b))
        self.assertEqual(len(parsers.ja3_hash(a)), 32)
        if parsers.ja3_hash(a) != OPENSSL_HASH:
            print(f"\n[!] OpenSSL дал другой JA3: {parsers.ja3_hash(a)} "
                  f"({parsers.ja3_string(a)}) — обнови rules.BROWSER_JA3", file=sys.stderr)

    def test_chrome_hello_split_across_records(self):
        full = build_client_hello()
        hs = full[5:]
        half = len(hs) // 2
        split = tls_record(22, hs[:half]) + tls_record(22, hs[half:])
        ch = parsers.parse_client_hello(split)
        self.assertEqual(parsers.ja3_hash(ch), CHROME_HASH)

    def test_malformed(self):
        with self.assertRaises(parsers.ParseError):
            parsers.parse_client_hello(build_client_hello()[:120])
        with self.assertRaises(parsers.ParseError):
            parsers.parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        with self.assertRaises(parsers.ParseError):
            parsers.parse_client_hello(b"")


class TestR1(unittest.TestCase):
    def test_wireguard_handshake(self):
        init = b"\x01\x00\x00\x00" + b"\x11" * 144
        resp = b"\x02\x00\x00\x00" + b"\x22" * 88
        self.assertEqual(len(init), 148)
        self.assertEqual(must(rules.r1_signature(init))[:2], ("R1", "drop"))
        self.assertEqual(must(rules.r1_signature(resp))[:2], ("R1", "drop"))
        self.assertIn("len=148", must(rules.r1_signature(init)).reason)

    def test_openvpn_reset(self):
        pkt = b"\x00\x2a" + b"\x38" + b"\x00" * 40   # opcode 7 = CONTROL_HARD_RESET_CLIENT_V2
        self.assertEqual(must(rules.r1_signature(pkt))[:2], ("R1", "drop"))

    def test_not_signature(self):
        self.assertIsNone(rules.r1_signature(b"GET / HTTP/1.1\r\n"))
        self.assertIsNone(rules.r1_signature(build_client_hello()))
        self.assertIsNone(rules.r1_signature(b"\x16" + b"\x00" * 147))  # 148 Б, но не WG


class TestR2(unittest.TestCase):
    def test_whitelist(self):
        self.assertIsNone(rules.r2_ja3(CHROME_HASH))
        self.assertEqual(rules.r2_ja3("0" * 32)[:2], ("R2", "drop"))

    def test_engine_drops_unknown_ja3(self):
        eng = engine.Engine()
        ch = build_client_hello(ciphers=[4865, 4866, 4867, 49195])  # не Chrome
        decs = eng.feed(1.0, 6, CLI, 40001, SRV, 443, ch)
        self.assertEqual([d.rule for d in decs], ["R2"])
        self.assertEqual(eng.feed(1.1, 6, SRV, 443, CLI, 40001, appdata(1400)), [])  # поток закрыт


class TestR3(unittest.TestCase):
    def _flow_with_ch(self, eng, t=1000.0):
        eng.feed(t, 6, CLI, 40001, SRV, 443, build_client_hello("t.example"))
        return eng.state.flow(6, CLI, 40001, SRV, 443, t)

    def test_small_then_large_fires(self):
        eng = engine.Engine()
        flow = self._flow_with_ch(eng)
        eng.feed(1000.2, 6, CLI, 40001, SRV, 443, appdata(517))          # inner ClientHello
        decs = eng.feed(1000.205, 6, SRV, 443, CLI, 40001, appdata(1400))  # ответ в 1 RTT
        self.assertEqual([d.rule for d in decs], ["R3"])
        self.assertEqual(flow.score, 1)

    def test_normal_http2_not_caught(self):
        eng = engine.Engine()
        self._flow_with_ch(eng)
        eng.feed(1000.2, 6, CLI, 40001, SRV, 443, appdata(45))    # SETTINGS
        eng.feed(1000.21, 6, CLI, 40001, SRV, 443, appdata(350))  # HEADERS
        decs = eng.feed(1000.33, 6, SRV, 443, CLI, 40001, appdata(1400))  # DATA через 120 мс
        self.assertEqual(decs, [])

    def test_large_record_alone(self):
        eng = engine.Engine()
        self._flow_with_ch(eng)
        decs = eng.feed(1000.2, 6, SRV, 443, CLI, 40001, appdata(1400))
        self.assertEqual(decs, [])

    def test_handshake_record_ignored(self):
        eng = engine.Engine()
        self._flow_with_ch(eng)
        decs = eng.feed(1000.2, 6, CLI, 40001, SRV, 443, tls_record(22, b"\x0e" * 100))
        self.assertEqual(decs, [])


class TestR4(unittest.TestCase):
    def test_fourth_connection_freezes(self):
        eng = engine.Engine()
        ch = build_client_hello("freeze.example")
        for i, t in enumerate((0.0, 10.0, 20.0)):
            decs = eng.feed(t, 6, CLI, 40100 + i, SRV, 443, ch)
            self.assertNotIn("R4", [d.rule for d in decs], f"сработало на {i + 1}-м")
        decs = eng.feed(30.0, 6, CLI, 40103, SRV, 443, ch)   # 4-е за 60 с
        self.assertEqual([d.rule for d in decs], ["R4"])
        self.assertEqual(decs[0].action, "freeze")
        self.assertTrue(eng.state.is_frozen(SRV, "freeze.example", 31.0))
        self.assertFalse(eng.state.is_frozen(SRV, "freeze.example", 30.0 + 120.0))

    def test_other_sni_not_counted(self):
        eng = engine.Engine()
        for i in range(4):
            decs = eng.feed(i, 6, CLI, 40200 + i, SRV, 443, build_client_hello(f"n{i}.example"))
            self.assertEqual(decs, [])

    def test_window_expires(self):
        eng = engine.Engine()
        ch = build_client_hello("slow.example")
        for i, t in enumerate((0.0, 10.0, 20.0, 70.0)):
            decs = eng.feed(t, 6, CLI, 40300 + i, SRV, 443, ch)
            self.assertEqual([d.rule for d in decs], [], f"сработало на t={t}")


class TestR5(unittest.TestCase):
    def test_udp_share_fires(self):
        eng = engine.Engine()
        for i in range(10):
            eng.feed(i * 0.01, 17, CLI, 5000, SRV, 443, b"u" * 6000)
        decs = []
        for i in range(15):
            decs += eng.feed(0.2 + i * 0.01, 6, CLI, 6000, SRV, 443, b"t" * 6000)
        self.assertEqual([d.rule for d in decs], ["R5"])
        self.assertIn("Мбит/с", decs[0].reason)
        self.assertGreater(eng.state.throttle_until, 0.0)

    def test_low_udp_share_silent(self):
        eng = engine.Engine()
        for i in range(2):
            eng.feed(i * 0.01, 17, CLI, 5000, SRV, 443, b"u" * 6000)
        decs = []
        for i in range(18):
            decs += eng.feed(0.2 + i * 0.01, 6, CLI, 6000, SRV, 443, b"t" * 6000)
        self.assertEqual(decs, [])

    def test_noise_floor(self):
        eng = engine.Engine()
        decs = eng.feed(0.0, 17, CLI, 5000, SRV, 443, b"u" * 1000)  # мало данных
        self.assertEqual(decs, [])


class TestPcapEndToEnd(unittest.TestCase):
    def test_pcap_mode_without_root(self):
        wg = b"\x01\x00\x00\x00" + b"\x33" * 144
        unknown = build_client_hello("bad.example", ciphers=[4865, 4866, 4867, 49195, 49196])
        self.assertNotIn(parsers.ja3_hash(parsers.parse_client_hello(unknown)), rules.BROWSER_JA3)
        frames = [
            (1.0, frame_udp(CLI, SRV, 51000, 443, wg)),
            (2.0, frame_tcp(CLI, SRV, 40001, 443, unknown)),
            (3.0, frame_tcp(CLI, SRV, 40002, 443, build_client_hello("ok.example"))),
        ]
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "t.pcap")
            write_pcap(path, frames)
            eng = engine.Engine()
            events = []
            engine.run_pcap(path, eng, lambda ts, flow, d: events.append((flow, d)))
            self.assertEqual(sorted({d.rule for _, d in events}), ["R1", "R2"])
            dropped = {f.client[1] for f, d in events if d.action == "drop"}
            self.assertEqual(dropped, {51000, 40001})
            self.assertNotIn(40002, dropped)

            out = io.StringIO()
            from dpi.main import main
            with contextlib.redirect_stdout(out):
                rc = main(["--pcap", path, "-q"])
            self.assertEqual(rc, 0)
            self.assertIn("потоков со срабатываниями: 2", out.getvalue())

    def test_broken_pcap(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.pcap")
            with open(path, "wb") as f:
                f.write(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)   # pcapng
            with self.assertRaises(ValueError):
                list(engine.read_pcap(path))


if __name__ == "__main__":
    unittest.main()
