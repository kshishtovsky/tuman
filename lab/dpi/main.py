"""CLI: python3 -m dpi.main --pcap f.pcap | --queue-num 0 [--rules R1,R3]."""
from __future__ import annotations

import argparse
import sys

from . import engine


def _emit(ts, flow, decision):
    print(f"{ts:12.3f} {decision.rule} {decision.action:6s} "
          f"{flow.client[0]}:{flow.client[1]} -> {flow.server[0]}:{flow.server[1]} "
          f"{flow.sni or '-'} {decision.reason}")


def _summary(eng):
    flows = [f for f in eng.state.flows.values() if f.hits]
    print(f"\nпотоков со срабатываниями: {len(flows)} из {len(eng.state.flows)}", file=sys.stdout)
    for f in flows:
        rules_hit = ",".join(sorted({r for _, r, _ in f.hits}))
        first = f.hits[0][0] - f.first_ts
        print(f"  score={f.score} правила={rules_hit} +{first:.3f}с "
              f"{f.client[0]}:{f.client[1]} -> {f.server[0]}:{f.server[1]} "
              f"{f.sni or '-'} ja3={f.ja3 or '-'}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dpi", description="эмулятор DPI/ТСПУ (R1–R5)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", metavar="FILE", help="офлайн-разбор pcap (без root)")
    src.add_argument("--queue-num", type=int, metavar="N", help="NFQUEUE номер (нужен root)")
    ap.add_argument("--rules", default=",".join(engine.ALL_RULES),
                    help="список активных правил, например R1,R3,R4")
    ap.add_argument("-q", "--quiet", action="store_true", help="только итог")
    args = ap.parse_args(argv)

    enabled = [r.strip().upper() for r in args.rules.split(",") if r.strip()]
    bad = set(enabled) - set(engine.ALL_RULES)
    if bad:
        ap.error(f"неизвестные правила: {','.join(sorted(bad))}")

    eng = engine.Engine(enabled)
    emit = None if args.quiet else _emit
    if args.pcap:
        try:
            engine.run_pcap(args.pcap, eng, emit)
        except (OSError, ValueError) as e:
            print(f"pcap: {e}", file=sys.stderr)
            return 2
    else:
        return engine.run_queue(args.queue_num, eng, emit)
    _summary(eng)
    return 0


if __name__ == "__main__":
    sys.exit(main())
