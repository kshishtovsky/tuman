#!/usr/bin/env bash
# Установка обвязки TMN/1 рядом с работающими Caddy / 3x-ui / hysteria.
# Ничего не перезапускает, портов не занимает, чужие конфиги не правит:
# только новые файлы в своих каталогах. Всё, что требует решения владельца,
# печатается в чек-листе в конце.
set -euo pipefail

SRC=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DRY=0
DOMAIN=${TMN_DOMAIN:-}

COVER_DIR=/var/www/tmn
SNIPPET_DIR=/etc/caddy/tmn
SNIPPET=$SNIPPET_DIR/10-tmn.caddy
CADDYFILE=/etc/caddy/Caddyfile
UNIT=/etc/systemd/system/tmns.service
SYSCTL=/etc/sysctl.d/90-tmn.conf
DROPIN_DIR=/etc/systemd/system/caddy.service.d
TODO=()

usage() {
	cat <<'EOF'
install.sh [--dry-run] [--domain ИМЯ]
  --dry-run, -n   показать действия, ничего не менять
  --domain ИМЯ    домен прикрытия (или переменная TMN_DOMAIN)
EOF
}

log() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '[warn] %s\n' "$*" >&2; }
todo() { TODO+=("$*"); }
die() {
	printf '[fail] %s\n' "$*" >&2
	exit 1
}
run() {
	if ((DRY)); then
		printf '  [dry]'
		printf ' %q' "$@"
		printf '\n'
	else
		"$@"
	fi
}

while (($#)); do
	case $1 in
	--dry-run | -n) DRY=1 ;;
	--domain)
		DOMAIN=${2:-}
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "неизвестный аргумент: $1 (см. --help)" ;;
	esac
	shift
done

# --- 1. проверки до любых изменений -----------------------------------------
if ((!DRY)); then
	[ "$(id -u)" -eq 0 ] || die "нужен root (или запусти с --dry-run)"
fi

# Домен попадает в Environment= и в путь серта: только буквы/цифры/дефис/точка.
if [ -n "$DOMAIN" ]; then
	[[ $DOMAIN =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] ||
		die "домен '$DOMAIN' не похож на FQDN"
fi

[ -r /etc/os-release ] || die "нет /etc/os-release — это не Linux?"
# shellcheck disable=SC1091
. /etc/os-release
case ${ID:-} in
ubuntu | debian) note "ОС: ${PRETTY_NAME:-$ID}" ;;
*) warn "ОС ${ID:-?} не Ubuntu/Debian — пути, unit и пакеты проверь вручную" ;;
esac

command -v systemctl >/dev/null || die "нет systemd"
command -v ss >/dev/null || die "нет ss (пакет iproute2)"
command -v df >/dev/null || die "нет df"
[ -f "$SRC/Caddyfile.tmn" ] || die "нет $SRC/Caddyfile.tmn — запускай скрипт из каталога deploy/"
[ -f "$SRC/tmns.service" ] || die "нет $SRC/tmns.service"
[ -f "$SRC/cover/index.html" ] || die "нет $SRC/cover/index.html"

command -v caddy >/dev/null || warn "caddy не найден в PATH: сниппет не проверен, validate сделай на сервере"

avail_kb=$(df -Pk / | awk 'NR==2 {print $4}')
if ((avail_kb < 2097152)); then
	warn "свободно ${avail_kb} КБ на / — меньше 2 ГБ (на VPS диск уже 82 %)"
	todo "освободить место на / (нужно ≥ 1 ГБ под логи/тейл, см. hardening.md)"
fi

tcp_busy() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }
udp_busy() { ss -Hlun "sport = :$1" 2>/dev/null | grep -q .; }

if tcp_busy 443; then
	warn "443/tcp занят: $(ss -Hltnp 'sport = :443' 2>/dev/null | head -1)"
	todo "решить, кто слушает 443/tcp (сейчас Caddy): оставить Caddy и дать tmns свой порт в /etc/tmn/tmns.toml, либо освободить 443 вручную"
else
	note "443/tcp свободен"
fi

if udp_busy 443; then
	warn "443/udp занят: $(ss -Hlunp 'sport = :443' 2>/dev/null | head -1)"
	todo "освободить 443/udp для QUIC (в Caddy это HTTP/3) или задать tmns другой QUIC-порт"
else
	note "443/udp свободен"
fi

# --- 2. пользователь и каталоги ---------------------------------------------
if id -u tmn >/dev/null 2>&1; then
	note "пользователь tmn уже существует"
else
	run useradd --system --user-group --no-create-home \
		--home-dir /var/lib/tmn --shell /usr/sbin/nologin tmn
fi
run install -d -o tmn -g tmn -m 0750 /var/lib/tmn /var/log/tmn
run install -d -o root -g root -m 0755 "$COVER_DIR" "$SNIPPET_DIR"

# --- 3. статика прикрытия ----------------------------------------------------
for f in index.html 404.html; do
	[ -f "$SRC/cover/$f" ] || continue
	run install -C -o root -g root -m 0644 "$SRC/cover/$f" "$COVER_DIR/$f"
done

# --- 4. сниппет Caddy (сам Caddyfile не правим) ------------------------------
run install -C -o root -g root -m 0644 "$SRC/Caddyfile.tmn" "$SNIPPET"

import_ok=0
if [ -f "$CADDYFILE" ] && grep -qE '^[[:space:]]*import[[:space:]]+/etc/caddy/tmn/\*\.caddy' "$CADDYFILE"; then
	import_ok=1
	note "import сниппета уже есть в $CADDYFILE"
else
	todo "добавить в $CADDYFILE ровно одну строку:  import /etc/caddy/tmn/*.caddy  (правку делает владелец)"
fi

if [ -n "$DOMAIN" ]; then
	run install -d -o root -g root -m 0755 "$DROPIN_DIR"
	if ((DRY)); then
		printf '  [dry] запись %s/10-tmn-env.conf: Environment=TMN_DOMAIN=%s\n' "$DROPIN_DIR" "$DOMAIN"
	else
		printf '[Service]\nEnvironment=TMN_DOMAIN=%s\n' "$DOMAIN" \
			>"$DROPIN_DIR/10-tmn-env.conf"
		chmod 0644 "$DROPIN_DIR/10-tmn-env.conf"
	fi
	note "домен прикрытия: $DOMAIN"
	todo "systemctl daemon-reload && systemctl restart caddy — чтобы Caddy увидел TMN_DOMAIN (рестарт рвёт текущие сессии)"
else
	todo "задать домен прикрытия: TMN_DOMAIN в окружении Caddy (drop-in) или заменить плейсхолдер в $SNIPPET"
fi

if ((import_ok)) && command -v caddy >/dev/null && ((!DRY)); then
	if caddy validate --config "$CADDYFILE" --adapter caddyfile >/tmp/tmn-caddy-validate.log 2>&1; then
		note "caddy validate: OK"
	else
		warn "caddy validate не прошёл — смотри /tmp/tmn-caddy-validate.log; Caddy НЕ перезагружался"
	fi
fi

# --- 5. sysctl ---------------------------------------------------------------
run install -C -o root -g root -m 0644 "$SRC/sysctl.d/90-tmn.conf" "$SYSCTL"

if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
	note "bbr в ядре доступен"
else
	warn "bbr недоступен в ядре — строку tcp_congestion_control из $SYSCTL убираю"
	if ((!DRY)); then
		sed -i '/^net\.ipv4\.tcp_congestion_control/d' "$SYSCTL"
	fi
	todo "modprobe tcp_bbr (+ /etc/modules-load.d/tcp_bbr.conf) и повторить install.sh, иначе CC останется прежним"
fi

shopt -s nullglob
for f in /etc/sysctl.d/*.conf; do
	if [ "$f" = "$SYSCTL" ]; then
		continue
	fi
	if grep -qE '^(net\.ipv4\.tcp_congestion_control|net\.core\.default_qdisc)' "$f"; then
		warn "в $f уже задан CC/qdisc; наш 90-tmn.conf применяется позже и перекроет его"
	fi
done
shopt -u nullglob

if ((!DRY)); then
	sysctl -q -e -p "$SYSCTL" || warn "не все ключи применились (ядро 6.8 поддерживает все, кроме, возможно, новых)"
fi

# --- 6. ufw: только добавление правил, ничего не удаляем ----------------------
if command -v ufw >/dev/null; then
	if ufw status 2>/dev/null | grep -q '^Status: active'; then
		run ufw allow 443/tcp comment 'tmn https'
		run ufw allow 443/udp comment 'tmn quic'
	else
		note "ufw не активен — правила не добавлял"
		todo "если включишь ufw: ufw allow 443/tcp && ufw allow 443/udp"
	fi
else
	warn "ufw не установлен — открой 443/tcp и 443/udp своим фаерволом"
fi

# --- 7. systemd unit: ставим и включаем, но НЕ стартуем ----------------------
run install -C -o root -g root -m 0644 "$SRC/tmns.service" "$UNIT"
run systemctl daemon-reload
run systemctl enable tmns.service
note "tmns.service: enabled, не запущен (ConditionPathExists=/etc/tmn/tmns.toml)"

# --- 8. чек-лист -------------------------------------------------------------
todo "положить бинарь в /usr/local/bin/tmns (root:root 0755) и создать /etc/tmn/tmns.toml"
todo "после правки Caddyfile: caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && systemctl reload caddy"
todo "прогнать deploy/probe.sh --domain <домен> --ip <IP> и сверить вердикты"
todo "пройти deploy/hardening.md (панель не на публичном IP, fail2ban, ключи, логи)"

log "установка завершена (изменений в существующих сервисах: 0)"
if ((${#TODO[@]})); then
	printf '\nОсталось вручную:\n'
	i=0
	for t in "${TODO[@]}"; do
		i=$((i + 1))
		printf '  %2d. %s\n' "$i" "$t"
	done
else
	printf '\nРучных шагов нет.\n'
fi
