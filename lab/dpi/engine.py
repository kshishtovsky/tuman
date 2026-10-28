"""Склейка правил в один обработчик + два источника пакетов: pcap и NFQUEUE.

NFQUEUE ходим по raw netlink (stdlib), python-nfqueue не нужен.
"""
from __future__ import annotations

import socket
import struct
import sys
import time

from . import parsers, rules
from .state import State

ALL_RULES = ("R1", "R2", "R3", "R4", "R5")

NF_ACCEPT, NF_DROP = 1, 0

NETLINK_NETFILTER = 12
NFNL_SUBSYS_NETFILTER = 1
NFQNL_MSG_PACKET, NFQNL_MSG_VERDICT, NFQNL_MSG_CONFIG = 0, 1, 2
NLM_F_REQUEST, NLM_F_ACK = 0x01, 0x04
NLMSG_ERROR = 2

NFQA_PACKET_HDR, NFQA_VERDICT_HDR = 1, 2
NFQA_CFG_CMD, NFQA_CFG_PARAMS, NFQA_CFG_QUEUE_MAXLEN = 1, 2, 3
NFQA_PAYLOAD = 10
NFQNL_CFG_CMD_BIND = 1
NFQNL_COPY_PACKET = 2


class Engine:
    def __init__(self, enabled=ALL_RULES):
        self.enabled = set(enabled)
        self.state = State()
        self.events = []  # (ts, flow, decision)

    def feed(self, ts, proto, src, sport, dst, dport, payload, nbytes=None):
        """Прогон одного пакета. Возвращает список сработавших правил."""
        flow = self.state.flow(proto, src, sport, dst, dport, ts)
        if flow.verdict == "drop" or self.state.is_frozen(flow.server[0], flow.sni, ts):
            return []

        decs = []
        c2s = (src, sport) == flow.client
        first = c2s and payload and not flow.ch_seen

        if first and "R1" in self.enabled:
            d = rules.r1_signature(payload)
            if d:
                decs.append(d)

        if first and payload[0] == 0x16:
            try:
                ch = parsers.parse_client_hello(payload)
            except parsers.ParseError:
                ch = None
            if ch:
                flow.ch_seen = True
                flow.sni = ch.sni
                flow.ja3 = parsers.ja3_hash(ch)
                if "R2" in self.enabled:
                    d = rules.r2_ja3(flow.ja3)
                    if d:
                        decs.append(d)
                if "R4" in self.enabled:
                    d = rules.r4_behaviour(self.state, flow.server[0], flow.sni, ts)
                    if d:
                        decs.append(d)

        if "R3" in self.enabled and payload:
            try:
                recs = parsers.tls_records(payload)
            except parsers.ParseError:
                recs = []
            for r in recs:
                d = rules.r3_tls_in_tls(flow, ts, r.ctype, r.size)
                if d:
                    decs.append(d)

        if "R5" in self.enabled:
            d = rules.r5_udp_share(self.state, ts, nbytes or len(payload) + 40, proto == 17)
            if d:
                decs.append(d)

        for d in decs:
            flow.hit(ts, d)
            self.events.append((ts, flow, d))
        return decs


# --- pcap -----------------------------------------------------------------
LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL = 1, 101, 113


def _strip_l2(data, linktype):
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        off, et = 14, struct.unpack_from("!H", data, 12)[0]
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        return data[off:] if et == 0x0800 else None
    if linktype == LINKTYPE_LINUX_SLL:
        return data[16:] if len(data) > 16 else None
    return data  # RAW / NULL считаем готовым IP


def read_pcap(path):
    """Классический pcap. pcapng не поддержан — shortcut, конвертить tcpdump -w -P."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("pcap: файл короче заголовка")
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("pcap: неизвестная сигнатура (pcapng?)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            sec, frac, incl, _ = struct.unpack(endian + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            frame = _strip_l2(data, linktype)
            if frame:
                yield sec + (frac / 1e9 if nano else frac / 1e6), frame


def _feed_frame(engine, ts, frame):
    try:
        ip = parsers.parse_ipv4(frame)
        if ip.proto == 6:
            l4 = parsers.parse_tcp(ip.payload)
            payload = l4.payload
        elif ip.proto == 17:
            l4 = parsers.parse_udp(ip.payload)
            payload = l4.payload
        else:
            return None, []
    except parsers.ParseError:
        return None, []
    decs = engine.feed(ts, ip.proto, ip.src, l4.sport, ip.dst, l4.dport,
                       payload, nbytes=len(frame))
    return engine.state.flow(ip.proto, ip.src, l4.sport, ip.dst, l4.dport, ts), decs


def run_pcap(path, engine, emit=None):
    for ts, frame in read_pcap(path):
        flow, decs = _feed_frame(engine, ts, frame)
        if emit:
            for d in decs:
                emit(ts, flow, d)
    return engine


# --- NFQUEUE через netlink ------------------------------------------------
def _nlmsg(mtype, seq, payload, flags=NLM_F_REQUEST):
    return struct.pack("!IHHII", 16 + len(payload), mtype, flags, seq, 0) + payload


def _nla(atype, data):
    size = 4 + len(data)
    return struct.pack("!HH", size, atype) + data + b"\0" * (-size % 4)


def _attrs(payload):
    off = 0
    while off + 4 <= len(payload):
        size, atype = struct.unpack_from("!HH", payload, off)
        if size < 4:
            return
        yield atype & 0x3FFF, payload[off + 4:off + size]
        off += (size + 3) & ~3


class NFQueue:
    """Очередь nfnetlink_queue: bind, recv, verdict. Нужен root/CAP_NET_ADMIN."""

    def __init__(self, num, family=socket.AF_INET):
        self.num = num
        self.family = family
        self.seq = int(time.time())
        if not hasattr(socket, "AF_NETLINK"):
            raise OSError("NFQUEUE есть только на Linux, на этой машине используй --pcap")
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind((0, 0))

    def _send(self, mtype, payload, flags=NLM_F_REQUEST):
        self.seq += 1
        self.sock.send(_nlmsg((NFNL_SUBSYS_NETFILTER << 8) | mtype, self.seq, payload, flags))
        return self.seq

    def _ack(self, seq):
        while True:
            for mtype, payload in self._messages(self.sock.recv(1 << 16)):
                if mtype == NLMSG_ERROR:
                    err = struct.unpack_from("!i", payload, 0)[0]
                    if err:
                        raise OSError(-err, "netlink: %s" % _errno_text(-err))
                    return
                if mtype == (NFNL_SUBSYS_NETFILTER << 8) | NFQNL_MSG_PACKET:
                    continue

    def _messages(self, data):
        off = 0
        while off + 16 <= len(data):
            size, mtype, _flags, _seq, _pid = struct.unpack_from("!IHHII", data, off)
            if size < 16 or off + size > len(data):
                return
            yield mtype, data[off + 16:off + size]
            off += (size + 3) & ~3

    def bind(self, maxlen=4096):
        body = struct.pack("!BBH", self.family, 0, self.num)
        body += _nla(NFQA_CFG_CMD, bytes([NFQNL_CFG_CMD_BIND]))
        body += _nla(NFQA_CFG_PARAMS, struct.pack("!IB", 0xFFFF, NFQNL_COPY_PACKET))
        body += _nla(NFQA_CFG_QUEUE_MAXLEN, struct.pack("!I", maxlen))
        seq = self._send(NFQNL_MSG_CONFIG, body, NLM_F_REQUEST | NLM_F_ACK)
        self._ack(seq)

    def recv(self):
        while True:
            for mtype, payload in self._messages(self.sock.recv(1 << 18)):
                if mtype != (NFNL_SUBSYS_NETFILTER << 8) | NFQNL_MSG_PACKET:
                    continue
                attrs = dict(_attrs(payload[4:]))
                if NFQA_PAYLOAD not in attrs:
                    continue
                packet_id = struct.unpack_from("!I", attrs[NFQA_PACKET_HDR], 0)[0]
                return packet_id, attrs[NFQA_PAYLOAD]

    def verdict(self, packet_id, verdict, mark=None):
        body = struct.pack("!BBH", self.family, 0, self.num)
        body += _nla(NFQA_VERDICT_HDR, struct.pack("!I", verdict))
        if mark is not None:
            body += _nla(3, struct.pack("!I", mark))  # NFQA_MARK
        self._send(NFQNL_MSG_VERDICT, body)

    def close(self):
        self.sock.close()


def _errno_text(err):
    import errno
    return errno.errorcode.get(err, str(err))


def run_queue(num, engine, emit=None):
    try:
        q = NFQueue(num)
        q.bind()
    except OSError as e:
        print(f"nfqueue: {e}\n"
              f"нужен root/CAP_NET_ADMIN и правило nft queue num {num}; "
              f"без root используй --pcap", file=sys.stderr)
        return 2
    try:
        while True:
            packet_id, frame = q.recv()
            flow, decs = _feed_frame(engine, time.time(), frame)
            drop = any(d.action in ("drop", "freeze") for d in decs)
            q.verdict(packet_id, NF_DROP if drop else NF_ACCEPT)
            if emit:
                for d in decs:
                    emit(time.time(), flow, d)
    except KeyboardInterrupt:
        return 0
    finally:
        q.close()
