# tools: как мерить маршрут хостинга

Два маленьких Go-бинаря. Ничего не требуют на сервере (кроме открытого порта), не зависят от шифров и протоколов — меряют голый канал.

## 1. TCP: raw down / up

На сервере (Linux, любой хостинг):
```bash
scp -P <port> tools/bin/chan_linux user@host:/tmp/chan
ssh user@host 'chmod +x /tmp/chan; sudo ufw allow 8092/tcp; sudo ufw allow 8093/tcp'
ssh user@host 'dd if=/dev/zero of=/tmp/t200.bin bs=1M count=200 status=none'
ssh user@host 'setsid -f /tmp/chan serve 8092 /tmp/t200.bin >/tmp/serve.log 2>&1'
ssh user@host 'setsid -f /tmp/chan sink 8093 >/tmp/sink.log 2>&1'
```

С домашней машины:
```bash
tools/bin/chan.exe get host:8092 200          # скачивание 200 МБ, один поток
tools/bin/chan.exe push host:8093 200         # отдача 200 МБ, один поток
seq 4 | xargs -P4 -I{} tools/bin/chan.exe get host:8092 200   # 4 потока, агрегат
ssh user@host 'cat /tmp/sink.log'             # сервер покажет source IP: домашний = шли напрямую
```

## 2. UDP: где начинаются потери

```bash
ssh user@host 'sudo ufw allow 8094/udp; setsid -f /tmp/udp usink 8094 10 >/tmp/usink.log 2>&1'
tools/bin/udp.exe ublast host:8094 10 250     # 10 с, целевые 250 Мбит/с
ssh user@host 'cat /tmp/usink.log'            # сколько реально дошло
```
Прогнать на 150 / 250 / 400 и сравнить с TCP. Если UDP доставляет заметно меньше — QUIC/Hysteria2 на этом маршруте смысла не имеет.

## 3. Правила корректного замера

- Тестировать **напрямую**, мимо туннеля: проверять, что сервер видит домашний source IP (в логе sink/serve). Иначе меряешь свой VPN, а не канал.
- Всегда 1 поток **и** 4 потока: разница показывает, упирается ли в congestion control или в полосу.
- 200 МБ минимум, 2 прогона: первый часто разогревочный.
- Не пользоваться браузерными спидтестами: они меряют CDN и кэш, а не маршрут до твоего VPS.

## 4. Порог решения

down ≥ 600 Мбит/с одним потоком — маршрут годится под цель G1 (700+).
down 250–400 — цель G1 переписывается на реальную (или ищем другой хостинг).
down < 200 — маршрут негоден, менять провайдера/локацию.
