# deploy/ — серверная обвязка TMN/1

Ставится **рядом** с уже работающими Caddy (`mylifemyrulesonline.ru`), 3x-ui, hysteria
и tproxy. Жёсткое требование: существующие сервисы продолжают работать как работали.
Поэтому здесь только новые файлы в своих каталогах; ни один чужой конфиг не правится.

## Состав

| Файл | Куда на сервере | Что делает |
|---|---|---|
| `Caddyfile.tmn` | `/etc/caddy/tmn/10-tmn.caddy` | сайт-прикрытие: TLS, статика, 404, `log discard` |
| `cover/index.html`, `cover/404.html` | `/var/www/tmn/` | статика прикрытия (4.9 КБ), без единого упоминания прокси |
| `tmns.service` | `/etc/systemd/system/tmns.service` | юнит демона: `User=tmn`, 1 capability, `ProtectSystem=strict` |
| `sysctl.d/90-tmn.conf` | `/etc/sysctl.d/90-tmn.conf` | tcp_rmem 16 МБ, BBR+fq, file-max |
| `install.sh` | — | идемпотентная установка, `--dry-run`, ничего не стартует |
| `probe.sh` | — | 10 проб активного зондирования, таблица PASS/FAIL |
| `hardening.md` | — | чек-лист: панель, fail2ban, ключи, логи, порты |

## Порядок

```bash
# 1. посмотреть, что будет сделано (ничего не меняет, root не нужен)
./install.sh --dry-run --domain notes.example.org

# 2. установить (root): пользователь tmn, каталоги, статика, сниппет, sysctl, ufw, unit
sudo ./install.sh --domain notes.example.org

# 3. владелец добавляет в /etc/caddy/Caddyfile ОДНУ строку и проверяет конфиг
#    import /etc/caddy/tmn/*.caddy
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy        # reload, не restart: текущие сессии не рвутся

# 4. бинарь и конфиг демона — вручную (install.sh их не создаёт)
sudo install -m 0755 tmns /usr/local/bin/tmns
sudo install -d -m 0750 -o root -g tmn /etc/tmn
sudo install -m 0640 -o root -g tmn tmns.toml /etc/tmn/tmns.toml
sudo systemctl start tmns

# 5. проверка поведения
./probe.sh --domain notes.example.org --ip <IP>
```

`import` — единственная правка основного Caddyfile. Директива допускается только
в глобальной области (не внутри `site { }`), поэтому строка ставится в начало файла,
до первого блока сайта. Сниппет с одним блоком сайта; глобальных опций в нём нет,
поэтому настройки существующих сайтов он не затрагивает.

## Домен прикрытия

Сниппет берёт имя из окружения процесса Caddy: `{$TMN_DOMAIN:tmn.example.invalid}`.
`install.sh --domain notes.example.org` создаёт drop-in
`/etc/systemd/system/caddy.service.d/10-tmn-env.conf` с `Environment=TMN_DOMAIN=...`
(отдельный файл, не правка чужого юнита). Чтобы Caddy его увидел:
`systemctl daemon-reload && systemctl restart caddy` — это решение владельца,
`install.sh` рестарт не делает. Плейсхолдер `tmn.example.invalid` выбран намеренно:
если домен не задан, Caddy не сможет получить серт и это будет видно сразу, а не тихо.

## Порты: что решает владелец, а не скрипт

`install.sh` проверяет 443/tcp и 443/udp и **не занимает** их. На этом VPS:

- **443/tcp** уже слушает Caddy с `mylifemyrulesonline.ru`. Варианты: оставить Caddy
  владельцем 443 и дать tmns свой порт в `/etc/tmn/tmns.toml`, либо освободить 443
  вручную (перенос сайта, второй IP). Скрипт ничего не переключает.
- **443/udp** обычно занят HTTP/3 того же Caddy. Для QUIC либо отключить h3 у Caddy,
  либо дать tmns другой UDP-порт.

Пока `/etc/tmn/tmns.toml` не существует, юнит не стартует вообще
(`ConditionPathExists`), поэтому `enable` безопасен: демон не полезет в занятый порт
и не будет флапать. Плюс `StartLimitBurst=5` на 5 минут — если порт всё же занят,
systemd сдастся, а не будет долбиться.

## Почему это не ломает существующее

- `install.sh` не пишет в `/etc/caddy/Caddyfile`, `/etc/systemd/system/caddy.service`,
  конфиги x-ui/hysteria; не делает `systemctl restart|stop` никому, кроме `daemon-reload`.
- Ни одного `rm -rf`; только `install -C` (перезапись лишь при отличии) и `install -d`.
- ufw: только `allow 443/tcp` и `allow 443/udp` — оба порта уже нужны существующему
  Caddy, так что доступность не меняется; ни одно правило не удаляется.
- sysctl: файлы из `/usr/lib/sysctl.d` не правятся; если CC/qdisc уже задан в другом
  файле — предупреждение в выводе. Строка BBR вырезается, если ядро её не знает.
- Новый пользователь `tmn`, свои каталоги, свой юнит: конфликтов имён нет.

## Откат

```bash
sudo systemctl disable --now tmns
sudo rm -f /etc/systemd/system/tmns.service /etc/caddy/tmn/10-tmn.caddy \
           /etc/sysctl.d/90-tmn.conf /etc/systemd/system/caddy.service.d/10-tmn-env.conf
sudo rm -rf /var/www/tmn /var/lib/tmn /var/log/tmn
sudo userdel tmn && sudo systemctl daemon-reload && sudo systemctl reload caddy
```
Строку `import` из Caddyfile убирает владелец — её ставил он же.
sysctl-значения после удаления файла живут до перезагрузки (или `sysctl --system`).

## Ограничения, которые надо помнить

- `Caddyfile.tmn` проверен вручную: бинаря `caddy` на машине разработки нет,
  `caddy validate` не запускался. На сервере — обязательный шаг из п.3.
- Caddy не имеет директивы `default_server`: на неизвестный SNI он отдаёт серт
  первого (по порядку в конфиге) сайта. Проба 3 в `probe.sh` показывает фактическое
  поведение; если там серт чужого домена, а нужен наш — владелец добавляет
  `default_sni <наш домен>` в глобальный блок своего Caddyfile.
- В core-Caddy нет rate-limit: без tmns 20 соединений с одного IP обслуживаются как у
  обычного статического сайта. Сам `tmns` держит лимит 30 новых соединений с IP в
  минуту и отвечает 429-страницей как nginx (проба 10 в `probe.sh`): если на порту
  Caddy, проба покажет 0×429 и красный вердикт — это ожидаемо и означает «лимита нет».
- Пробы 6–7 (AUTH) имеют смысл, когда на порту слушает tmns. Если на 443 Caddy,
  они проверяют поведение прикрытия, а не демона.
