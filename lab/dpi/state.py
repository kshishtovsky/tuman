"""Состояние, живущее дольше одного пакета: потоки, цели R4, полоса R5."""
from __future__ import annotations

from collections import deque

IDLE_TIMEOUT = 120.0  # поток без пакетов забываем


class Flow:
    __slots__ = ("proto", "client", "server", "first_ts", "last_ts", "sni", "ja3",
                 "score", "hits", "ch_seen", "verdict", "small_ts", "app_bytes")

    def __init__(self, proto, src, sport, dst, dport, ts):
        self.proto = proto
        self.client = (src, sport)
        self.server = (dst, dport)
        self.first_ts = self.last_ts = ts
        self.sni = ""
        self.ja3 = ""
        self.score = 0
        self.hits = []
        self.ch_seen = False
        self.verdict = None      # "drop" — поток больше не пропускаем
        self.small_ts = None     # R3: время малой записи, ждущей крупную
        self.app_bytes = 0       # R3: сколько прикладных байт уже видели

    @property
    def key(self):
        return (self.proto,) + self.client + self.server

    def hit(self, ts, decision):
        self.score += decision.score
        self.hits.append((ts, decision.rule, decision.reason))
        if decision.action in ("drop", "freeze"):
            self.verdict = "drop"


class State:
    def __init__(self):
        self.flows = {}
        self.targets = {}   # (ip, sni) -> deque[ts]  R4
        self.frozen = {}    # (ip, sni) -> until      R4
        self.bw = deque()   # (ts, bytes, is_udp)     R5
        self.throttle_until = 0.0

    def flow(self, proto, src, sport, dst, dport, ts) -> Flow:
        key = (proto, src, sport, dst, dport)
        f = self.flows.get(key)
        if f is None:
            f = self.flows.get((proto, dst, dport, src, sport))
        if f is None:
            f = Flow(proto, src, sport, dst, dport, ts)
            self.flows[key] = f
            if len(self.flows) & 0xFF == 0:
                self._gc(ts)
        f.last_ts = ts
        return f

    def _gc(self, ts):
        dead = [k for k, f in self.flows.items() if ts - f.last_ts > IDLE_TIMEOUT]
        for k in dead:
            del self.flows[k]

    # --- R4 ---------------------------------------------------------------
    def touch_target(self, ip, sni, ts, window):
        q = self.targets.setdefault((ip, sni), deque())
        q.append(ts)
        while q and ts - q[0] > window:
            q.popleft()
        return len(q)

    def freeze(self, ip, sni, ts, duration):
        self.frozen[(ip, sni)] = ts + duration

    def is_frozen(self, ip, sni, ts):
        if not sni:
            return False
        until = self.frozen.get((ip, sni))
        return until is not None and ts < until

    # --- R5 ---------------------------------------------------------------
    def add_bw(self, ts, nbytes, is_udp, window):
        self.bw.append((ts, nbytes, is_udp))
        while self.bw and ts - self.bw[0][0] > window:
            self.bw.popleft()
        total = sum(n for _, n, _ in self.bw)
        udp = sum(n for _, n, u in self.bw if u)
        return (udp / total if total else 0.0), total
