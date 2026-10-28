#!/usr/bin/env bash
# 10 проб активного зондирования: ведёт себя сервер как обычный сайт или нет.
# Только чтение: ничего не устанавливает и не меняет, чужие сервисы не трогает.
# Пробы 6-7 (AUTH) осмысленны только если на порту слушает tmns, а не Caddy.
set -euo pipefail

DOMAIN=${TMN_DOMAIN:-}
IP=${TMN_IP:-}
PORT=${TMN_PORT:-443}
FOREIGN=${TMN_FOREIGN_SNI:-www.example.com}
T=${TMN_TIMEOUT:-10}

usage() {
	cat <<'EOF'
probe.sh --domain D [--ip 1.2.3.4] [--port 443] [--foreign-sni имя]
  --domain       домен прикрытия (обязательно)
  --ip           адрес сервера (по умолчанию — резолв домена)
  --port         порт TLS (по умолчанию 443)
  --foreign-sni  чужой SNI для пробы 3 (по умолчанию www.example.com)
EOF
}

die() {
	printf '[fail] %s\n' "$*" >&2
	exit 2
}

while (($#)); do
	case $1 in
	--domain)
		DOMAIN=${2:-}
		shift
		;;
	--ip)
		IP=${2:-}
		shift
		;;
	--port)
		PORT=${2:-}
		shift
		;;
	--foreign-sni)
		FOREIGN=${2:-}
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "неизвестный аргумент: $1" ;;
	esac
	shift
done

[ -n "$DOMAIN" ] || {
	usage
	die "нужен --domain"
}
command -v curl >/dev/null || die "нет curl"
command -v openssl >/dev/null || die "нет openssl"
if [ -z "$IP" ]; then
	IP=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 {print $1}') || true
	[ -n "$IP" ] || die "не резолвится $DOMAIN — укажи --ip"
fi
[[ $IP == *:* ]] && BASE="[$IP]" || BASE=$IP

NAME=() EXP=() GOT=() VER=()

record() { # имя, ожидание, факт, 1|0
	NAME+=("$1")
	EXP+=("$2")
	GOT+=("$3")
	if [ "$4" = 1 ]; then VER+=("PASS"); else VER+=("FAIL"); fi
}

url() { printf 'https://%s:%s%s' "$DOMAIN" "$PORT" "$1"; }

http() { # путь [доп. аргументы curl]
	local p=$1
	shift
	curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time "$T" \
		--resolve "$DOMAIN:$PORT:$IP" "$@" "$(url "$p")" || printf '000 -'
}

status_of() { printf '%s' "${1%% *}"; }

# 0. базовый серт: наш эталон для проб 3-4
OURS=$(openssl s_client -connect "$BASE:$PORT" -servername "$DOMAIN" </dev/null 2>/dev/null |
	openssl x509 -noout -fingerprint -sha256 2>/dev/null) || OURS=""
[ -n "$OURS" ] || die "нет TLS-ответа от $IP:$PORT — сервер не отвечает на $DOMAIN"

# 1. правильный SNI + GET /
r=$(http /)
code=$(status_of "$r")
size=$(curl -s --max-time "$T" --resolve "$DOMAIN:$PORT:$IP" "$(url /)" | wc -c)
if [ "$code" = 200 ] && [ "$size" -gt 500 ]; then record "свой SNI + GET /" "200 и HTML" "$code, ${size}B" 1
else record "свой SNI + GET /" "200 и HTML" "$code, ${size}B" 0; fi

# 2. правильный SNI + GET /случайный
path=/$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')
code=$(status_of "$(http "$path")")
if [ "$code" = 404 ]; then record "свой SNI + GET $path" "404" "$code" 1
else record "свой SNI + GET $path" "404" "$code" 0; fi

# 3. чужой SNI: свой серт, никакого alert
out=$(openssl s_client -connect "$BASE:$PORT" -servername "$FOREIGN" </dev/null 2>&1) || true
fp=$(printf '%s' "$out" | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || fp=""
if [ -n "$fp" ] && [ "$fp" = "$OURS" ]; then
	record "чужой SNI ($FOREIGN)" "наш серт, handshake ok" "серт наш" 1
elif [ -n "$fp" ]; then
	record "чужой SNI ($FOREIGN)" "наш серт, handshake ok" "серт другого сайта" 0
else
	record "чужой SNI ($FOREIGN)" "наш серт, handshake ok" "нет серта/alert" 0
fi

# 4. пустой SNI
out=$(openssl s_client -connect "$BASE:$PORT" -noservername </dev/null 2>&1) || true
if printf '%s' "$out" | grep -q 'BEGIN CERTIFICATE\|SHA256 Fingerprint'; then
	record "пустой SNI" "серт отдан, alert нет" "серт отдан" 1
else
	record "пустой SNI" "серт отдан, alert нет" "обрыв/alert" 0
fi

# 5. TLS 1.2 вместо 1.3: обычный сайт пускает, значит и мы
v12=$(openssl s_client -connect "$BASE:$PORT" -servername "$DOMAIN" -tls1_2 </dev/null 2>&1 |
	grep -o 'Protocol *: *TLSv1\.2' | head -1) || v12=""
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$T" --tlsv1.2 --tls-max 1.2 \
	--resolve "$DOMAIN:$PORT:$IP" "$(url /)" || printf 000)
if [ -n "$v12" ] && [ "$code" = 200 ]; then record "TLS 1.2 (клиент без 1.3)" "TLSv1.2 + 200" "TLSv1.2 + $code" 1
else record "TLS 1.2 (клиент без 1.3)" "TLSv1.2 + 200" "${v12:-нет 1.2} + $code" 0; fi

# 6-7. невалидный AUTH и его повтор: 50 байт мусора вместо AUTH-кадра (spec §4), затем обычный GET
BAD='00010000000069f2a1b31122334455667788abababababababababababababababababababababababababababababababab'
bogus() { # 50 байт: ver=1, ts, nonce, мусорный tag
	local h=$BAD
	while [ -n "$h" ]; do
		printf '%b' "\\x${h:0:2}"
		h=${h:2}
	done
}
auth_then_get() {
	{ bogus; sleep 0.3; printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$DOMAIN"; } |
		timeout $((T + 10)) openssl s_client -quiet -connect "$BASE:$PORT" -servername "$DOMAIN" 2>&1 || true
}
for n in 6 7; do
	[ "$n" = 6 ] && label="невалидный AUTH + GET /" || label="повтор того же AUTH"
	out=$(auth_then_get)
	first=$(printf '%s\n' "$out" | grep -m1 '^HTTP/' || true)
	alerts=$(printf '%s\n' "$out" | grep -ci 'alert\|reset by peer\|unexpected eof' || true)
	if [[ $first == HTTP/1.*\ 2* ]] && [ "$alerts" = 0 ]; then
		record "$label" "обычный 200, без alert/RST" "$first" 1
	else
		record "$label" "обычный 200, без alert/RST" "${first:-нет HTTP} (alert: $alerts)" 0
	fi
done

# 8. 20 соединений подряд с одного IP
pids=()
tmpd=$(mktemp -d)
for i in $(seq 20); do
	curl -s -o /dev/null -w '%{http_code}\n' --max-time "$T" \
		--resolve "$DOMAIN:$PORT:$IP" "$(url /)" >"$tmpd/$i" &
	pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || true; done
ok20=$(cat "$tmpd"/* 2>/dev/null | grep -c '^200$' || true)
rm -f "$tmpd"/*
rmdir "$tmpd"
if [ "$ok20" = 20 ]; then record "20 соединений с одного IP" "20/20 без 429 и бана" "$ok20/20" 1
else record "20 соединений с одного IP" "20/20 без 429 и бана" "$ok20/20" 0; fi

# 9. HTTP/1.1 keep-alive, пауза 15 с
out=$( {
	printf 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' "$DOMAIN"
	sleep 15
	printf 'GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$(date +%s)" "$DOMAIN"
} | timeout $((T + 30)) openssl s_client -quiet -connect "$BASE:$PORT" -servername "$DOMAIN" 2>&1 || true)
n=$(printf '%s\n' "$out" | grep -c '^HTTP/' || true)
if [ "$n" = 2 ]; then record "keep-alive idle 15 с" "оба ответа пришли" "2 ответа" 1
else record "keep-alive idle 15 с" "оба ответа пришли" "$n ответ(ов)" 0; fi

# 10. огромный POST (64 МиБ): отказ, но без падения сервиса
r=$(head -c 67108864 /dev/zero |
	curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 30 -X POST --data-binary @- \
		--resolve "$DOMAIN:$PORT:$IP" "$(url /)" || printf '000 -')
code=$(status_of "$r")
code2=$(status_of "$(http /)")
case $code in
405 | 413 | 400) ok=1 ;;
*) ok=0 ;;
esac
[ "$code2" = 200 ] || ok=0
record "POST 64 МиБ на /" "405/413, сервис жив" "$code, дальше $code2" "$ok"

# итог
fail=0
printf '\n%-3s %-32s %-28s %-26s %s\n' '#' 'Проба' 'Ожидание' 'Факт' 'Вердикт'
printf '%s\n' '-------------------------------------------------------------------------------------------------------------'
for i in "${!NAME[@]}"; do
	printf '%-3s %-32s %-28s %-26s %s\n' "$((i + 1))" "${NAME[$i]}" "${EXP[$i]}" "${GOT[$i]}" "${VER[$i]}"
	[ "${VER[$i]}" = PASS ] || fail=$((fail + 1))
done
printf '\nPASS %s / %s\n' "$((${#NAME[@]} - fail))" "${#NAME[@]}"
exit $((fail > 0))
