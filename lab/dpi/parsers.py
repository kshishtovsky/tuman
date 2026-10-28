"""Разбор IPv4/TCP/UDP и TLS ClientHello по байтам. Только stdlib.

Правила эмулятора смотрят на 5-tuple, длины TLS-записей и JA3 — больше ничего
не нужно, поэтому scapy не тянем.
"""
from __future__ import annotations

import hashlib
import struct
from typing import NamedTuple


class ParseError(Exception):
    """Не наш формат: вызывающий просто не применяет правило."""


class IPv4(NamedTuple):
    src: str
    dst: str
    proto: int
    payload: bytes


class TCPSegment(NamedTuple):
    sport: int
    dport: int
    seq: int
    flags: int
    payload: bytes


class UDPSegment(NamedTuple):
    sport: int
    dport: int
    payload: bytes


class TLSRecord(NamedTuple):
    ctype: int
    version: int
    size: int
    body: bytes


class ClientHello(NamedTuple):
    version: int
    ciphers: list
    extensions: list
    curves: list
    point_formats: list
    sni: str


def _ip(raw: bytes) -> str:
    return "%d.%d.%d.%d" % tuple(raw)


def parse_ipv4(buf: bytes) -> IPv4:
    if len(buf) < 20:
        raise ParseError("ipv4: короткий заголовок")
    if buf[0] >> 4 != 4:
        raise ParseError("ipv4: не версия 4")
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        raise ParseError("ipv4: битый IHL")
    total = struct.unpack_from("!H", buf, 2)[0]
    if 0 < total <= len(buf):
        buf = buf[:total]  # ethernet-паддинг в pcap
    if struct.unpack_from("!H", buf, 6)[0] & 0x3FFF:
        raise ParseError("ipv4: фрагмент (не собираем)")
    return IPv4(_ip(buf[12:16]), _ip(buf[16:20]), buf[9], buf[ihl:])


def parse_tcp(buf: bytes) -> TCPSegment:
    if len(buf) < 20:
        raise ParseError("tcp: короткий заголовок")
    sport, dport, seq = struct.unpack_from("!HHI", buf, 0)
    doff = (buf[12] >> 4) * 4
    if doff < 20 or len(buf) < doff:
        raise ParseError("tcp: битый data offset")
    return TCPSegment(sport, dport, seq, buf[13], buf[doff:])


def parse_udp(buf: bytes) -> UDPSegment:
    if len(buf) < 8:
        raise ParseError("udp: короткий заголовок")
    sport, dport, length = struct.unpack_from("!HHH", buf, 0)
    end = min(len(buf), length) if length >= 8 else len(buf)
    return UDPSegment(sport, dport, buf[8:end])


TLS_CONTENT_TYPES = (20, 21, 22, 23, 24)


def tls_records(buf: bytes) -> list:
    """Записи TLS из буфера потока. Неполная хвостовая запись отбрасывается."""
    if len(buf) < 5:
        raise ParseError("tls: нет заголовка записи")
    ctype, ver, size = struct.unpack_from("!BHH", buf, 0)
    if ctype not in TLS_CONTENT_TYPES or ver >> 8 != 3:
        raise ParseError("tls: не TLS-запись")
    out, off = [], 0
    while off + 5 <= len(buf):
        ctype, ver, size = struct.unpack_from("!BHH", buf, off)
        if ctype not in TLS_CONTENT_TYPES or ver >> 8 != 3:
            break
        end = off + 5 + size
        if end > len(buf):
            break
        out.append(TLSRecord(ctype, ver, size, buf[off + 5:end]))
        off = end
    return out


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _u16(b: bytes, o: int) -> int:
    if o + 2 > len(b):
        raise ParseError("tls: обрыв на u16")
    return (b[o] << 8) | b[o + 1]


def _parse_sni(data: bytes) -> str:
    if len(data) < 2:
        return ""
    end = min(len(data), 2 + _u16(data, 0))
    o = 2
    while o + 3 <= end:
        ntype = data[o]
        nlen = _u16(data, o + 1)
        o += 3
        if ntype == 0:
            return data[o:o + nlen].decode("ascii", "replace")
        o += nlen
    return ""


def parse_client_hello(buf: bytes) -> ClientHello:
    """ClientHello из начала TCP-потока (возможно, склеенный из записей)."""
    recs = tls_records(buf)
    hs = b"".join(r.body for r in recs if r.ctype == 22)
    if len(hs) < 4 or hs[0] != 1:
        raise ParseError("tls: нет ClientHello")
    body_len = int.from_bytes(hs[1:4], "big")
    if len(hs) - 4 < body_len:
        raise ParseError("tls: ClientHello обрезан")
    body = hs[4:4 + body_len]

    version = _u16(body, 0)
    o = 2 + 32                      # legacy_version + random
    o += 1 + body[o]                # session_id
    cs_len = _u16(body, o)
    o += 2
    ciphers = [_u16(body, i) for i in range(o, o + cs_len - 1, 2)]
    o += cs_len
    o += 1 + body[o]                # compression_methods

    extensions, curves, point_formats, sni = [], [], [], ""
    if o + 2 <= len(body):
        ext_end = min(len(body), o + 2 + _u16(body, o))
        o += 2
        while o + 4 <= ext_end:
            etype, elen = _u16(body, o), _u16(body, o + 2)
            o += 4
            data = body[o:o + elen]
            o += elen
            extensions.append(etype)
            if etype == 0:
                sni = _parse_sni(data)
            elif etype == 10 and len(data) >= 2:
                curves = [_u16(data, i) for i in range(2, 2 + _u16(data, 0) - 1, 2)]
            elif etype == 11 and data:
                point_formats = list(data[1:1 + data[0]])
    return ClientHello(version, ciphers, extensions, curves, point_formats, sni)


def ja3_string(ch: ClientHello) -> str:
    def join(xs):
        return "-".join(str(x) for x in xs if not is_grease(x))

    return ",".join((str(ch.version), join(ch.ciphers), join(ch.extensions),
                     join(ch.curves), join(ch.point_formats)))


def ja3_hash(ch: ClientHello) -> str:
    return hashlib.md5(ja3_string(ch).encode()).hexdigest()
