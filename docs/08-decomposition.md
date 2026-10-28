# 08. Декомпозиция: этап 2 (MVP) и кто что делает

Репозиторий: `E:\JP\tuman`, ветка `exp/tmn`. `main`/`dev` в `E:\rupas` не трогаем никогда; перенос логики в rupas — отдельный этап 6, после того как MVP заработает.

## Правила ветвления

```
exp/tmn                  интеграционная ветка (всё сходится сюда)
  ├── feat/proto-core    протокол + mux
  ├── feat/lab-dpi       эмулятор DPI
  ├── feat/deploy        серверная обвязка (Caddy, systemd, ufw)
  ├── feat/server        tmns (бинарь сервера)
  └── feat/client        tmnc (бинарь клиента)
```
Каждый субагент работает только в своей ветке, мержит сам в `exp/tmn` (fast-forward или squash), после зелёных тестов.

## Дерево задач

### W0 — контракт (сделано)
- T0.1 wire spec v0.1 (кадр, AUTH, окна, Go-интерфейсы) → `docs/07-proto-v1-spec.md` ✅
- T0.2 решение по репозиторию: отдельный чистый, потом перенос в rupas ✅

### W1 — параллельно, без взаимных зависимостей

**T1.1 `proto` + `mux` (ветка `feat/proto-core`)**
- `proto/header.go`: Header, MarshalTo, ParseHeader, ReadFrame, WriteFrame, валидация по §2.
- `proto/auth.go`: AuthTag, MakeAuth, VerifyAuth, replay-LRU.
- `mux/session.go`: writer-loop (один goroutine, батчинг), reader-loop, диспетчеризация по stream, WU, таймауты, PING.
- `mux/stream.go`: io.ReadWriteCloser, окна, FIN/CLOSE, SetUrgent.
- Тесты: `proto/frame_test.go` (roundtrip, границы, битые заголовки), `proto/auth_test.go` (валидный/просроченный/подменённый тег, replay), `mux/stream_test.go` (эхо-пары в памяти через net.Pipe: 1 поток, 100 потоков, закрытие, окна), бенчмарк `BenchmarkFrameRoundtrip` и `BenchmarkMuxThroughput` (доложить ns/op и allocs/op).
- DoD: `go test ./... -race` зелёный, `allocs/op == 0` на roundtrip кадра, пропускная способность in-memory ≥ 2 Гбит/с на поток.

**T1.2 Эмулятор DPI (`feat/lab-dpi`)**
- `lab/dpi/` — обработчик nfqueue (Python 3 или Go), правила R1–R5 из `docs/04-lab-plan.md`.
- `lab/netns.sh` — создание netns-стенда (cli/rtr/srv), tc netem, nftables queue.
- `lab/Dockerfile` — образ с привилегиями для запуска на VPS (локально Docker не работает — проверить только сборкой).
- `lab/test_rules.py` — юнит-тесты парсеров (ClientHello/JA3, детект «мелкая запись → крупная», счётчик параллельных соединений) на синтетических pcap-фрагментах.
- DoD: тесты зелёные; `lab/netns.sh` синтаксически проверен `bash -n`; README с командой запуска.

**T1.3 Серверная обвязка (`feat/deploy`)**
- `deploy/Caddyfile`: домен, сайт-прикрытие, TLS, `default_server`-поведение, проксирование на `tmns` по ALPN/пути не требуется (tmns слушает свой порт).
- `deploy/tmns.service`, `deploy/tmnc` не нужен (клиент локальный).
- `deploy/install.sh`: ufw (443/tcp, 443/udp), sysctl (tcp_rmem 16 МБ, BBR, fq), лимиты, создание пользователя, каталоги.
- `deploy/hardening.md`: чек-лист (нет панели на публичном IP, fail2ban, ключи, ротация).
- `deploy/probe.sh`: 10 проб активного зондирования (свой/чужой/пустой SNI, HTTP-пути, невалидный AUTH) с ожидаемыми ответами.
- DoD: `bash -n` на всех скриптах, Caddyfile проходит `caddy validate` (если бинаря нет — проверить парсером `caddy adapt` или документировать), probe.sh описан в README.

### W2 — после мержа T1.1 (нужен `mux`)

**T2.1 server (`feat/server`)**
- `cmd/tmns`: TLS 1.3 listener (серт из файла), `mux.Session` в серверном режиме.
- Фолбэк на сайт-прикрытие: нет валидного AUTH за 2 с → HTTP-ответ из `deploy/cover/`.
- Egress: `OpenStream` → `net.Dial` к цели, двунаправленная копия, таймауты, отмена.
- Логи: без адресов/URL, только объёмы/коды/RTT.
- DoD: интеграционный тест `cmd/tmns` + `mux` в памяти; проверка фолбэка тестом (нет AUTH → отдан HTML).

**T2.2 client (`feat/client`)**
- `cmd/tmnc`: TLS 1.3 dial (uTLS-отпечаток Chrome, fallback на crypto/tls при недоступности модуля — с TODO), `mux.Session` в клиентском режиме.
- Локальный SOCKS5 (без авторизации, только CONNECT; UDP ASSOCIATE — заглушка с ошибкой).
- Конфиг: YAML/JSON (host, port, sni, psk, insecure?). PSK из файла, не из CLI-аргумента.
- DoD: `curl --socks5-hostname` через `tmnc` до сайта работает в тесте с локальным `tmns`; `go test -race` зелёный.

### W3 — измерение и приёмка

**T3.1 bench (`feat/bench`)**: `cmd/tmnbench` — throughput через туннель (1 поток, 4 потока), CPU/RSS, сравнение с raw `chan`.
**T3.2 прогон E1–E4, E7** из `docs/04-lab-plan.md` на стенде и, если получится, на VPS.
**T3.3 отчёт** `docs/09-mvp-results.md` с числами и решением «идём в этап 3 или меняем дизайн».

### W4 — этап 3 (не сейчас)
WEB-режим, шейпер/профили, anti-probing hardening, мультиендпоинт.

## Порядок и гейты

```
W0 ──► W1 (T1.1, T1.2, T1.3 параллельно) ──► W2 (T2.1, T2.2 параллельно) ──► W3
```
Гейт W1→W2: `go test ./... -race` зелёный в `exp/tmn`, бенчмарк кадра с 0 allocs.
Гейт W2→W3: SOCKS5-запрос через туннель проходит, фолбэк на сайт-прикрытие подтверждён тестом.
Гейт W3→этап 3: ≥ 60 % от скорости raw `chan` на том же хосте, CPU ≤ 50 % ядра на 300 Мбит/с.

## Что требует владельца (не блокирует W1)

- Доступ к VPS для install.sh (нужен sudo — пароль вводит сам).
- Домен и сертификат для сайта-прикрытия (или берём существующий `mylifemyrulesonline.ru`).
- Решение: покупать ли почасовые VPS для поиска маршрута (`docs/06-route-matrix.md`).
