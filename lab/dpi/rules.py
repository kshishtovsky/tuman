"""R1–R5 из docs/04-lab-plan.md §2.

Каждая функция возвращает Decision или None. Действия: drop (рвём поток),
freeze (то же + заморозка цели на 120 с), score (только пометка).
"""
from __future__ import annotations

from typing import NamedTuple


class Decision(NamedTuple):
    rule: str
    action: str
    reason: str
    score: int = 1


# --- R1: сигнатуры --------------------------------------------------------
# WireGuard: type + 3 нулевых reserved; длины handshake фиксированы спeцом.
# shadowsocks пассивно не детектится (соль случайна) — не эмулируем, см. README.
WG_LEN = {1: 148, 2: 92, 3: 64}
OPENVPN_OPCODES = {7, 8, 9, 10, 11}  # CONTROL_HARD_RESET_*/CONTROL_*/ACK


def r1_signature(payload: bytes):
    if not payload:
        return None
    n = len(payload)
    if payload[0] in WG_LEN and payload[1:4] == b"\x00\x00\x00" and n == WG_LEN[payload[0]]:
        return Decision("R1", "drop", f"wireguard type={payload[0]} len={n}")
    if n >= 3 and payload[0] == 0:  # OpenVPN: 2 байта длины пакета, старший = 0
        opcode = payload[2] >> 3
        if opcode in OPENVPN_OPCODES:
            return Decision("R1", "drop", f"openvpn opcode={opcode}")
    return None


# --- R2: JA3-белый список -------------------------------------------------
BROWSER_JA3 = {
    "cd08e31494f9531f560d64c695473da9": "chrome",
    # OpenSSL 3 default: под ним ходит curl/python на стенде (эталон E1–E4).
    "37f7d09ced1a845dc48872abc1a29d7b": "openssl-default",
}


def r2_ja3(ja3: str):
    if ja3 in BROWSER_JA3:
        return None
    return Decision("R2", "drop", f"ja3={ja3} вне белого списка")


# --- R3: TLS-in-TLS -------------------------------------------------------
R3_SMALL = 700
R3_LARGE = 1200
R3_WINDOW = 0.050
R3_FIRST = 4096


def r3_tls_in_tls(flow, ts, ctype, size):
    """Малая запись, затем крупная в пределах 50 мс, в первых 4 КБ.

    shortcut: пара «малая -> крупная» ловит и быстрый HTTP/2 (ответ < 50 мс);
    это осознанная строгость эмулятора, для HTTP/2 с задержкой сервера не срабатывает.
    """
    if ctype != 23:
        return None
    decision = None
    if flow.app_bytes < R3_FIRST:
        if size < R3_SMALL:
            flow.small_ts = ts
        elif size > R3_LARGE:
            if flow.small_ts is not None and ts - flow.small_ts <= R3_WINDOW:
                decision = Decision(
                    "R3", "score",
                    f"малая -> крупная запись {size} Б за {1000 * (ts - flow.small_ts):.0f} мс")
            flow.small_ts = None
    flow.app_bytes += size
    return decision


# --- R4: поведение --------------------------------------------------------
R4_COUNT = 3
R4_WINDOW = 60.0
R4_FREEZE = 120.0


def r4_behaviour(state, ip, sni, ts):
    if not sni:
        return None
    n = state.touch_target(ip, sni, ts, R4_WINDOW)
    if n > R4_COUNT:
        state.freeze(ip, sni, ts, R4_FREEZE)
        return Decision("R4", "freeze",
                        f"{n} TLS к {ip}/{sni} за {R4_WINDOW:.0f}с -> заморозка {R4_FREEZE:.0f}с")
    return None


# --- R5: доля UDP ---------------------------------------------------------
R5_SHARE = 0.40
R5_WINDOW = 10.0
R5_MIN_BYTES = 1 << 16  # ниже этого шума не считаем
R5_RATE = 5e6
R5_THROTTLE = 10.0


def r5_udp_share(state, ts, nbytes, is_udp):
    share, total = state.add_bw(ts, nbytes, is_udp, R5_WINDOW)
    if ts < state.throttle_until or total < R5_MIN_BYTES or share <= R5_SHARE:
        return None
    state.throttle_until = ts + R5_THROTTLE
    return Decision("R5", "score",
                    f"udp {share:.0%} из {total} Б за {R5_WINDOW:.0f}с -> {R5_RATE / 1e6:.0f} Мбит/с")
