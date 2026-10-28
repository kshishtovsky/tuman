# lab — эмулятор DPI/ТСПУ (этап 1)

Пять правил из `docs/04-lab-plan.md` §2, стенд на netns и `tc netem`, без внешних
зависимостей (Python 3.11+ stdlib). Нужен, чтобы воспроизводить срабатывание
конкретного правила и мерить `score` и время до первого срабатывания (E3, E4).

```
cli --- veth --- rtr (netem 15 мс + nfqueue DPI) --- veth --- srv
```

## Файлы

| Файл | Что |
|---|---|
| `dpi/parsers.py` | IPv4/TCP/UDP, TLS-записи, ClientHello → SNI, JA3 |
| `dpi/state.py` | таблица потоков по 5-tuple, цели R4, окно полосы R5 |
| `dpi/rules.py` | R1–R5 отдельными функциями → `Decision(rule, action, reason)` |
| `dpi/engine.py` | склейка правил, `--pcap` (офлайн) и NFQUEUE по raw netlink |
| `dpi/main.py` | CLI |
| `netns.sh` | стенд cli/rtr/srv, veth, маршруты, netem, nft queue bypass |
| `test_rules.py` | unittest: парсеры на реальных байтах + R1–R5 |
| `Dockerfile`, `docker-compose.yml` | прогон на VPS (privileged/NET_ADMIN) |

## Локально, без root (pcap-режим)

```bash
cd lab
python3 -m unittest -v test_rules.py          # 25 тестов, root не нужен
python3 -m dpi.main --pcap captures/run.pcap          # разбор записанного трафика
python3 -m dpi.main --pcap run.pcap --rules R1,R4 -q  # только часть правил, без построчно
```

Снять pcap (на Linux, где стенд или живой клиент):

```bash
tcpdump -i any -w run.pcap 'tcp port 443 or udp port 443'
# pcapng не читаем: tcpdump -w ... -P (pcap) или конвертировать
```

Вывод: по строке на срабатывание (`время, правило, действие, 5-tuple, SNI, причина`)
и итог по потокам — `score`, набор правил, задержка от первого пакета.

## На VPS / в Docker

```bash
docker compose build
docker compose run --rm dpi python3 -m unittest -v test_rules.py   # тесты в образе
docker compose up -d dpi
docker compose exec dpi bash

# внутри контейнера:
./netns.sh up
python3 -m dpi.main --queue-num 0 -v &     # обработчик очереди
./netns.sh test                            # проверить связность cli -> srv
ip netns exec cli curl -k https://10.20.0.1/
./netns.sh status                          # адреса, netem, nft
./netns.sh down
```

`netns.sh up` сам поднимает `ip_forward`, отключает `rp_filter` и вешает
`nft ... queue num 0 bypass`. `bypass` обязателен: если обработчик упал, стенд
продолжает работать, а не встаёт.

Параметры канала — переменными окружения:

```bash
DELAY=30ms LOSS=2% RATE=100mbit QNUM=1 ./netns.sh up
```

## Правила

| # | Что ловит | Действие |
|---|---|---|
| R1 | WireGuard handshake (type 1/2/3 + нулевой reserved + длина 148/92/64), OpenVPN opcode | drop |
| R2 | JA3 вне белого списка (`rules.BROWSER_JA3`) | drop |
| R3 | запись < 700 Б, затем > 1200 Б в пределах 50 мс, в первых 4 КБ | score +1 |
| R4 | > 3 TLS к одной паре (IP, SNI) за 60 с | заморозка 120 с |
| R5 | доля UDP > 40 % за 10 с (от 64 КБ) | score +1, помечает троттлинг |

### Добавить правило

1. В `dpi/rules.py` — функция, возвращающая `Decision("R6", "drop"|"score", reason)`
   или `None`. Константы порогов держать рядом с функцией.
2. В `dpi/engine.py`: добавить `"R6"` в `ALL_RULES` и вызов в `Engine.feed`
   (для состояния — поле в `Flow`/`State`, `dpi/state.py`).
3. В `test_rules.py` — положительный и отрицательный кейс; тест на реальных
   байтах (см. `ssl_client_hello` — ClientHello от OpenSSL через `ssl.MemoryBIO`).
4. Если правило требует данных, которых нет в пакете (расшифровка, время жизни
   соединения) — писать в README, что оно приблизительное.

## Чем эмулятор отличается от живого ТСПУ

- R1: shadowsocks пассивно не детектится (соль случайна) — в эмуляторе его нет.
  WireGuard/OpenVPN — по структуре первого пакета, как в ТСПУ.
- R2: JA3 считаем по ClientHello, белый список из двух профилей (Chrome,
  OpenSSL-дефолт под curl/python стенда). Живой ТСПУ обновляет списки и смотрит
  ещё на порядок ALPN/record sizes.
- R3: пара «малая → крупная» без расшифровки. Ложное срабатывание на быстром
  HTTP/2 (ответ < 50 мс) — осознанно: эмулятор строже, обход должен выживать
  при строгом детекте. Живой ТСПУ добавляет энтропию и статистику по потоку.
- R4: счёт по (dst IP, SNI) из ClientHello; ТСПУ считает ещё и по /24 и по
  сертификату.
- R5: только помечает (`throttle_until`), реального шейпинга нет — для него нужен
  `tc` класс по fw-mark из verdict. В ТСПУ шейпинг аппаратный.
- Не эмулируем: active probing, QUIC/QUIC-in-TLS, DNS-фильтрацию, блокировку по
  IP-репутации. Для E7 (активное зондирование) эмулятор бесполезен.
