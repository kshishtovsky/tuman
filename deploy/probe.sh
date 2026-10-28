#!/usr/bin/env bash
# 10 проб активного зондирования (docs/03-system-design.md §4, задача T3.4):
# ведёт ли сервер себя как обычный сайт. Только чтение: ничего не устанавливает,
# чужие сервисы не трогает. Запускать снаружи VPS или с самого VPS.
#
# Лимит 30 новых соединений с IP в минуту считается на сервере и копится за прогон,
# поэтому повторный прогон в ту же минуту поймает 429 — дай минуту паузы.
set -uo pipefail

DOMAIN=${TMN_DOMAIN:-}
IP=${TMN_IP:-}
PORT=${TMN_PORT:-443}
FOREIGN=${TMN_FOREIGN_SNI:-www.example.com}
T=${TMN_TIMEOUT:-10}
INSECURE=${TMN_INSECURE:-0}

usage() {
	cat <<'EOF'
probe.sh --domain D [--ip 1.2.3.4] [--port 443] [--foreign-sni имя] [--insecure]
  --domain       домен прикрытия (обязательно)
  --ip           адрес сервера (по умолчанию — резолв домена)
  --port         порт TLS (по умолчанию 443)
  --foreign-sni  чужой SNI для пробы 3 (по умолчанию www.example.com)
  --insecure     не проверять цепочку серта (локальный прогон с самоподписанным)
  --timeout      таймаут отдельных запросов, с (по умолчанию 10)
EOF
}

die() {
	printf '[fail] %s\n' "$*" >&2
	exit 2
}

while (($#)); do
	case $1 in
	--domain) DOMAIN=${2:-}; shift ;;
	--ip) IP=${2:-}; shift ;;
	--port) PORT=${2:-}; shift ;;
	--foreign-sni) FOREIGN=${2:-}; shift ;;
	--timeout) T=${2:-}; shift ;;
	--insecure) INSECURE=1 ;;
	-h | --help) usage; exit 0 ;;
	*) die "неизвестный аргумент: $1" ;;
	esac
	shift
done

[ -n "$DOMAIN" ] || { usage; die "нужен --domain"; }
command -v curl >/dev/null || die "нет curl"
command -v openssl >/dev/null || die "нет openssl"
if [ -z "$IP" ]; then
	IP=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 {print $1}') || true
	[ -n "$IP" ] || die "не резолвится $DOMAIN — укажи --ip"
fi
[[ $IP == *:* ]] && BASE="[$IP]" || BASE=$IP

tmpd=$(mktemp -d)
trap 'rm -rf "$tmpd"' EXIT

NAME=() EXP=() GOT=() VER=()
rec() { # имя, ожидание, факт, 1|0
	NAME+=("$1")
	EXP+=("$2")
	GOT+=("$3")
	if [ "$4" = 1 ]; then VER+=(PASS); else VER+=(FAIL); fi
}

CURL=(curl -sS --max-time "$T" --resolve "$DOMAIN:$PORT:$IP")
[ "$INSECURE" = 1 ] && CURL+=(-k)
url() { printf 'https://%s:%s%s' "$DOMAIN" "$PORT" "$1"; }

# get PATH → CODE, VER, BODY (глобальные). Без временных файлов: curl на MSYS
# не умеет писать в /tmp из git-bash-пути.
get() {
	local out meta
	out=$("${CURL[@]}" -w '\n%{http_code} %{http_version}' "$(url "$1")" 2>/dev/null) || true
	meta=${out##*$'\n'}
	BODY=${out%$'\n'*}
	if [ "$meta" = "$out" ]; then # curl упал: строки меты в выводе нет
		CODE=000
		HVER=-
		BODY=""
		return
	fi
	CODE=${meta%% *}
	HVER=${meta##* }
}

# ssl_client SNI [опции s_client]; пустой SNI = без расширения
ssl_client() {
	local sni=$1
	shift
	if [ -n "$sni" ]; then
		openssl s_client -connect "$BASE:$PORT" -servername "$sni" "$@" </dev/null 2>&1
	else
		openssl s_client -connect "$BASE:$PORT" -noservername "$@" </dev/null 2>&1
	fi
}
fp() { openssl x509 -noout -fingerprint -sha256 2>/dev/null; }

# эталон: наш серт по своему SNI; без него остальные пробы бессмысленны
OURS=$(ssl_client "$DOMAIN" | fp || true)
[ -n "$OURS" ] || die "нет TLS-ответа от $BASE:$PORT на SNI $DOMAIN"

# 1. Свой SNI + GET /
get /
size=${#BODY}
if [ "$CODE" = 200 ] && [ "$size" -gt 0 ] && grep -qi '<html' <<<"$BODY"; then ok=1; else ok=0; fi
rec "свой SNI + GET /" "200 и HTML по h1" "HTTP $CODE, ${size}B, h$HVER" $ok

# 2. Свой SNI + неизвестный путь
path="/$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
get "$path"
[ "$CODE" = 404 ] && ok=1 || ok=0
rec "свой SNI + GET $path" "404 как у статики" "HTTP $CODE" $ok

# 3. Чужой SNI (fronting): серт наш, handshake не рвётся
THEIRS=$(ssl_client "$FOREIGN" | fp || true)
if [ -n "$THEIRS" ] && [ "$THEIRS" = "$OURS" ]; then ok=1; fact="серт наш, handshake ok"
elif [ -n "$THEIRS" ]; then ok=0; fact="серт чужого сайта"
else ok=0; fact="нет handshake/серта"; fi
rec "чужой SNI ($FOREIGN)" "наш серт, handshake ok" "$fact" $ok

# 4. Без SNI: TLS 1.3 не требует расширения — отдаём дефолтный серт
NONE=$(ssl_client "" | fp || true)
if [ -n "$NONE" ] && [ "$NONE" = "$OURS" ]; then ok=1; fact="серт наш, alert нет"
elif [ -n "$NONE" ]; then ok=0; fact="другой серт"
else ok=0; fact="обрыв/alert"; fi
rec "без SNI (по IP)" "наш серт, alert нет" "$fact" $ok

# 5. TLS 1.2: отказ на handshake, после него 1.3 работает
OUT12=$(ssl_client "$DOMAIN" -tls1_2 || true)
get /
if grep -q 'alert protocol version\|no protocols available\|handshake failure' <<<"$OUT12" &&
	! grep -q 'BEGIN CERTIFICATE' <<<"$OUT12" && [ "$CODE" = 200 ]; then ok=1; fact="alert, дальше 1.3: $CODE"
else ok=0; fact="нет отказа / сервер лёг: $CODE"; fi
rec "TLS 1.2 (клиент без 1.3)" "отказ на handshake" "$fact" $ok

# 6. Невалидный AUTH без запроса: 400 через idle-таймаут, не мгновенно
printf '\x08\x00\x00\x00\x00\x32\x00\x00' >"$tmpd/auth.bin" # AUTH, len=50
head -c 50 /dev/urandom >>"$tmpd/auth.bin"
t0=$(date +%s%3N)
first=$(timeout $((T + 10)) openssl s_client -quiet -connect "$BASE:$PORT" -servername "$DOMAIN" \
	2>/dev/null <"$tmpd/auth.bin" | head -1 || true)
t1=$(date +%s%3N)
ms=$((t1 - t0))
if [[ $first == "HTTP/1.1 400"* ]] && [ "$ms" -ge 1500 ] && [ "$ms" -le 8000 ]; then ok=1; else ok=0; fi
rec "невалидный AUTH (50Б мусора)" "400 через 2-5 с, без alert" "${first:-нет ответа} за ${ms} мс" $ok

# 7. Повтор AUTH + GET через 300 мс: как keep-alive сервер — сайт
first=$(
	{
		cat "$tmpd/auth.bin"
		sleep 0.3
		printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$DOMAIN"
	} | timeout $((T + 10)) openssl s_client -quiet -connect "$BASE:$PORT" -servername "$DOMAIN" 2>/dev/null | head -1 || true
)
[[ $first == "HTTP/1.1 200"* ]] && ok=1 || ok=0
rec "повтор AUTH + GET /" "200 сайт, AUTH_OK нет" "${first:-нет ответа}" $ok

# 8. keep-alive с паузой 15 с: оба запроса обслужены, RST нет
out=$(
	{
		printf 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' "$DOMAIN"
		sleep 15
		printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$DOMAIN"
	} | timeout $((T + 30)) openssl s_client -quiet -connect "$BASE:$PORT" -servername "$DOMAIN" 2>/dev/null || true
)
n=$(grep -c '^HTTP/1.1 200' <<<"$out" || true)
[ "$n" = 2 ] && ok=1 || ok=0
rec "idle 15 с в keep-alive" "2 ответа 200" "$n/2 ответа" $ok

# 9. Огромный POST (64 МиБ): отказ, сервис жив
post=$(head -c 67108864 /dev/zero | "${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST \
	--data-binary @- "$(url /)" 2>/dev/null)
get /
after=$CODE
case $post in
405 | 413 | 400 | 000) p=1 ;;
*) p=0 ;;
esac
[ "$after" = 200 ] && ok=1 || ok=0
[ "$p" = 1 ] || ok=0
rec "POST 64 МиБ на /" "405/413 или обрыв приёма, сервис жив" "POST ${post:-000}, после $after" $ok

# 10. Rate-limit: 40 соединений с одного IP → часть получает 429-страницу nginx
n200=0 n429=0 nbad=0
for i in $(seq 40); do
	get /
	case $CODE in
	200) n200=$((n200 + 1)) ;;
	429)
		n429=$((n429 + 1))
		grep -q '429 Too Many Requests' <<<"$BODY" || nbad=$((nbad + 1))
		;;
	*) nbad=$((nbad + 1)) ;;
	esac
done
if [ "$n429" -ge 1 ] && [ "$n200" -ge 1 ] && [ "$nbad" -eq 0 ]; then ok=1; else ok=0; fi
rec "40 соединений с одного IP" "200 до лимита, дальше 429-страница" "${n200}×200, ${n429}×429, брак $nbad" $ok

# итог
fail=0
printf '\n%-3s %-32s %-34s %-34s %s\n' '#' 'Проба' 'Ожидание' 'Факт' 'Вердикт'
printf '%s\n' '--------------------------------------------------------------------------------------------------------------'
for i in "${!NAME[@]}"; do
	printf '%-3s %-32s %-34s %-34s %s\n' "$((i + 1))" "${NAME[i]}" "${EXP[i]}" "${GOT[i]}" "${VER[i]}"
	[ "${VER[i]}" = PASS ] || fail=$((fail + 1))
done
printf '\nPASS %d / %d\n' "$((${#NAME[@]} - fail))" "${#NAME[@]}"
exit $((fail > 0))
