#!/usr/bin/env bash
# Стенд: cli --- rtr (netem + nfqueue) --- srv. Нужен root.
#   ./netns.sh up | down | status | test
set -euo pipefail

CLI_ADDR=10.10.0.1/24
RTR_CLI=10.10.0.2
SRV_ADDR=10.20.0.1/24
RTR_SRV=10.20.0.2
QNUM=${QNUM:-0}
DELAY=${DELAY:-15ms}
LOSS=${LOSS:-0.2%}
RATE=${RATE:-1gbit}

need_root() { [ "$(id -u)" -eq 0 ] || { echo "нужен root (netns/tc/nft)" >&2; exit 1; }; }

down() {
  for ns in cli rtr srv; do ip netns del "$ns" 2>/dev/null || true; done
}

up() {
  need_root
  down
  ip netns add cli; ip netns add rtr; ip netns add srv

  ip link add vc type veth peer name vr1
  ip link add vs type veth peer name vr2
  ip link set vc netns cli; ip link set vr1 netns rtr
  ip link set vs netns srv; ip link set vr2 netns rtr

  ip -n cli addr add "$CLI_ADDR" dev vc; ip -n cli link set vc up; ip -n cli link set lo up
  ip -n srv addr add "$SRV_ADDR" dev vs; ip -n srv link set vs up; ip -n srv link set lo up
  ip -n rtr addr add "$RTR_CLI/24" dev vr1; ip -n rtr link set vr1 up
  ip -n rtr addr add "$RTR_SRV/24" dev vr2; ip -n rtr link set vr2 up
  ip -n rtr link set lo up

  ip -n cli route add default via "$RTR_CLI"
  ip -n srv route add default via "$RTR_SRV"

  # forward + отключаем rp_filter: маршрут симметричный, но netns не любит строгий режим
  ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1
  ip netns exec rtr sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec rtr sysctl -qw net.ipv4.conf.default.rp_filter=0

  # netem на пути к серверу: RTT 30 мс
  ip netns exec rtr tc qdisc add dev vr2 root netem delay "$DELAY" loss "$LOSS" rate "$RATE"

  # nftables: очередь только для интересных портов, bypass — пакет идёт дальше,
  # если обработчик не успел/упал (иначе стенд встанет намертво)
  ip netns exec rtr nft add table inet dpi
  ip netns exec rtr nft 'add chain inet dpi fwd { type filter hook forward priority 0; policy accept; }'
  ip netns exec rtr nft add rule inet dpi fwd tcp dport 443 queue num "$QNUM" bypass
  ip netns exec rtr nft add rule inet dpi fwd udp dport 443 queue num "$QNUM" bypass

  echo "стенд поднят. cli=$CLI_ADDR srv=$SRV_ADDR queue=$QNUM"
  echo "  сервер в srv: ip netns exec srv python3 -m http.server 443 --bind 0.0.0.0 (или tls-сервер)"
  echo "  DPI:          sudo python3 -m dpi.main --queue-num $QNUM -v"
  echo "  трафик:       ip netns exec cli curl -k https://$SRV_ADDR/"
}

status() {
  need_root
  for ns in cli rtr srv; do
    printf '== %s\n' "$ns"
    ip -n "$ns" -brief addr 2>/dev/null || echo "нет netns"
  done
  ip netns exec rtr tc qdisc show dev vr2 2>/dev/null || true
  ip netns exec rtr nft list table inet dpi 2>/dev/null || true
}

test_traffic() {
  need_root
  ip netns exec srv python3 -m http.server 443 --bind 0.0.0.0 >/dev/null 2>&1 &
  local pid=$!
  sleep 1
  ip netns exec cli curl -sS -o /dev/null -w 'http: %{http_code} %{time_total}s\n' \
    "http://$SRV_ADDR/" || true
  kill "$pid" 2>/dev/null || true
}

case "${1:-up}" in
  up) up ;;
  down) need_root; down; echo "стенд убран" ;;
  status) status ;;
  test) test_traffic ;;
  *) echo "usage: $0 up|down|status|test" >&2; exit 2 ;;
esac
