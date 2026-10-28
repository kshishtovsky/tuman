# Hardening: чек-лист для VPS с TMN/1

Порядок — от «дёшево и обязательно» к «по желанию». Каждый пункт с командой проверки:
без проверки пункт не считается закрытым. Всё, что меняет системные файлы, делает
владелец вручную: `install.sh` эти файлы не трогает.

## 1. Панель 3x-ui не на публичном IP

- [ ] Панель слушает только loopback: `ss -ltnp | grep -E ':(8443|2053|2096)\b'` → адрес `127.0.0.1:%порт%`
      (в настройках x-ui: `webListen = 127.0.0.1`, `webDomain` не нужен).
- [ ] Снаружи порт закрыт: с чужой машины `nc -vz -w3 <IP> 8443` → `Connection refused`/timeout.
- [ ] Вход только туннелем: `ssh -L 8443:127.0.0.1:8443 root@<IP>`, затем `http://127.0.0.1:8443`.
- [ ] В ufw нет правил на порт панели: `ufw status numbered` → только 22, 443/tcp, 443/udp.

## 2. fail2ban

- [ ] Установлен и активен: `systemctl is-active fail2ban` → `active`.
- [ ] Jail для sshd включён: `fail2ban-client status sshd` → `Currently banned: N`, `Total banned: N`.
- [ ] `/etc/fail2ban/jail.d/10-tmn.local` (отдельный файл, не правит `jail.conf`):
      `[sshd] enabled = true`, `maxretry = 4`, `findtime = 10m`, `bantime = 1h`.
- [ ] Свой IP в `ignoreip` — иначе первый же неудачный вход закроет доступ.
- [ ] Проверка бана: `fail2ban-client set sshd banip 203.0.113.7` → `fail2ban-client status sshd`,
      затем `unbanip` (тестовый адрес из документации, не реальный клиент).

## 3. Ключи вместо паролей

- [ ] `/etc/ssh/sshd_config.d/10-tmn.conf` (новый файл): `PasswordAuthentication no`,
      `KbdInteractiveAuthentication no`, `PermitRootLogin prohibit-password`, `MaxAuthTries 3`.
- [ ] Синтаксис: `sshd -t` → без вывода.
- [ ] Применено: `sshd -T | grep -E 'passwordauthentication|permitrootlogin'` → `no` / `prohibit-password`.
- [ ] Пароль реально не пускает: `ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password root@<IP>`
      → `Permission denied (publickey)`.
- [ ] Ключ у каждого устройства свой (не один общий), комментарий вида `user@device@2026-10`.

## 4. Ротация ключей и секретов

- [ ] SSH-ключи: срок 6–12 месяцев. Порядок: добавить новый ключ → проверить вход →
      удалить старый из `authorized_keys` (не наоборот, иначе можно остаться без доступа).
- [ ] PSK TMN/1: ротация без переустановки (FR-12) — новый ключ в `/etc/tmn/tmns.toml`,
      `systemctl reload tmns` (или restart), старый убрать после подтверждения с клиента.
- [ ] TLS-серт: продление автоматическое (Caddy), проверка `caddy list-certificates` →
      `not_after` не ближе 30 дней; `curl -vI https://<домен> 2>&1 | grep expire`.
- [ ] Список подписок/конфигов на телефоне обновляется по ссылке, а не пересоздаётся руками.

## 5. Никакого логирования SNI / URL / адресов

- [ ] Наш сайт-прикрытие логи не пишет: в `deploy/Caddyfile.tmn` стоит `log { output discard }`;
      проверка `grep -A2 'log' /etc/caddy/tmn/10-tmn.caddy` — блока `output file` быть не должно.
- [ ] В основном Caddyfile нет глобального `log` с путями/URL для нашего домена:
      `grep -n 'log' /etc/caddy/Caddyfile`.
- [ ] Ротация/лимит journald (диск уже был на 82 %): в `/etc/systemd/journald.conf.d/10-tmn.conf`
      `SystemMaxUse=200M`, `MaxRetentionSec=1month`, затем `systemctl restart systemd-journald`.
- [ ] Демон пишет только объёмы/RTT/коды: `journalctl -u tmns -n 100 | grep -Ei 'https?://|sni|host:'`
      → пусто.
- [ ] Логи ufw выключены или без адресов назначения: `ufw status verbose | grep -i log` → `Logging: off`.
- [ ] Логи не уезжают в сторонний сервис: `grep -rn 'syslog\|remote' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null` → нет `@@`.

## 6. Новый демон не занял порт существующих сервисов

- [ ] Снимок ДО установки: `ss -ltnup > /root/ports-before.txt`.
- [ ] Снимок ПОСЛЕ установки: `ss -ltnup > /root/ports-after.txt`,
      `diff /root/ports-before.txt /root/ports-after.txt` → только новые строки с портом из `/etc/tmn/tmns.toml`.
- [ ] 443/tcp по-прежнему у Caddy: `ss -ltnp 'sport = :443'` → процесс `caddy`.
- [ ] tmns не в цикле рестартов: `systemctl show tmns -p NRestarts -p ActiveState` → `NRestarts=0`;
      если `failed` — смотри `journalctl -u tmns -n 50` (частые причины: порт занят, нет конфига, права на `/etc/tmn`).
- [ ] Существующие профили живы: панель открывается через туннель, текущий клиент подключается,
      `systemctl is-active x-ui hysteria-server` (имена юнитов уточнить: `systemctl list-units | grep -Ei 'x-ui|hysteria'`).
- [ ] Юнит ограничен: `systemd-analyze security tmns.service` → `Overall exposure level` в районе `2.x–3.x OK`
      (жёстче не выйдет: демон слушает сеть; при жалобах ослаблять точечно, а не снимать `ProtectSystem`).

## 7. Прочее, что стоит закрыть сразу

- [ ] ufw: `default deny incoming`, `default allow outgoing`, `allow 22/tcp` (или `limit 22/tcp`).
- [ ] `unattended-upgrades` для security-пакетов: `systemctl is-enabled unattended-upgrades` → `enabled`.
- [ ] Диск: `df -h /` → меньше 80 %; журналы и `/var/lib/tmn` не растут бесконечно.
- [ ] Никаких автообновлений демона из сети (SDD §10): бинарь меняется вручную, владельцем.
- [ ] `/etc/tmn/tmns.toml` — `chmod 0600`, владелец `tmn`, PSK не в git и не в командной строке (`--psk` не использовать).
