# 07. TMN/1 wire spec v0.1 (MVP, RAW-режим)

Нормативный документ. Всё, что ниже — обязательный контракт между клиентом и сервером. Изменения только через новую версию (`AUTH.ver`).

## 1. Транспорт

- TCP + TLS 1.3 (минимум TLS1.3, только AEAD: AES-128-GCM или ChaCha20-Poly1305).
- ALPN: `h2` (мимикрия под браузер), но HTTP/2-семантика в MVP **не используется** — после handshake идёт RAW-кадрирование. HTTP/2-инкапсуляция (режим WEB) — этап 3.
- Сервер обязан отвечать на обычный HTTP-запрос (без валидного AUTH) как сайт-прикрытие: 200 + HTML на `/`, 404 на прочее, без TLS alert и без RST.

## 2. Кадр

8 байт заголовка, big-endian, без varint:

```
offset 0: type    u8
offset 1: flags   u8
offset 2: stream  u16
offset 4: length  u16   // длина payload, 0..1400
offset 6: reserved u16  // =0, игнорируется при чтении
```

Типы:

| Код | Имя | Payload |
|---|---|---|
| 0x01 | DATA | данные потока |
| 0x02 | ACK | 4 байта: подтверждённый seq (для datagram-потоков) |
| 0x03 | PAD | произвольные байты, игнорируются |
| 0x04 | PING | 8 байт nonce, адресат обязан вернуть те же 8 байт |
| 0x05 | WU (window update) | 2 байта stream + 4 байта delta |
| 0x06 | FIN | пусто; закрывает направление записи потока |
| 0x07 | MIG | пусто (резерв, в MVP не отправляется, при получении — игнор) |
| 0x08 | AUTH | см. §4 |
| 0x09 | AUTH_OK | см. §4 |
| 0x0A | CLOSE | 1 байт reason |

Флаги (битовая маска):

| Бит | Имя | Смысл |
|---|---|---|
| 0x01 | OPEN | первый кадр потока, payload начинается с адреса (§3) |
| 0x02 | FIN | последние данные в этом направлении |
| 0x04 | MORE | продолжение сообщения (для datagram-потоков) |
| 0x08 | URGENT | интерактив: обходит шейпер/pacing, не задерживается коалесингом |

Правила валидации (нарушение = CLOSE с reason 0x01):
- `length > 1400` — ошибка;
- неизвестный `type` — ошибка;
- `stream` вне `[0, 0x7FFF]` — ошибка (старший бит зарезервирован);
- `OPEN` на уже открытом stream — ошибка;
- `DATA` на неоткрытом stream — ошибка;
- `flags` с неизвестными битами — игнорировать (forward compat), не ошибка.

## 3. Потоки и открытие

- stream 0 — управляющий (AUTH, PING, WU для соединения). DATA на stream 0 запрещён.
- Клиент открывает нечётные stream (1,3,5…), сервер — чётные (2,4,6…). Начало с 1.
- Открытие: `DATA` с флагом `OPEN`, payload:
  ```
  atyp u8        1=IPv4 (4 байта), 2=domain (1 байт len + len байт), 3=IPv6 (16 байт)
  addr ...
  port u16
  [данные, если есть]
  ```
- Закрытие: `FIN` (полузакрытие) и/или `CLOSE` (сброс). После `FIN` в обе стороны stream освобождается.

## 4. Аутентификация

Клиент, сразу после TLS handshake, отправляет один кадр `AUTH` на stream 0:

```
payload (50 байт):
  ver      u16   = 1
  ts       u64   = unix seconds
  nonce    u8[8]
  tag      u8[32]
```

`tag = HMAC-SHA256(psk, label || exporter || ver || ts || nonce)[0:32]`,

Порядок байт (обязателен для интеропа): `ver` и `ts` — big-endian, как в заголовке кадра.
`label` — `"TMN1-AUTH"` без нуль-терминатора. `nonce` — 8 байт как есть.
где `label = "TMN1-AUTH"` (ASCII, 9 байт), `client_random` — 32 байта из TLS 1.3 ClientHello (клиент и сервер обязаны брать одно и то же значение; в Go — `tls.ConnectionState` не отдаёт client_random, поэтому **MVP: client_random заменяется на 32-байтовый TLS exporter** `ExportKeyingMaterial("TMN1-AUTH-RANDOM", nil, 32)`; обе стороны его вычисляют из сессии).

Проверка на сервере:
- `ver == 1`, `|now - ts| <= 120 c`, `tag` совпадает (constant-time), replay-счётчик `(ts, nonce)` в LRU на 5 минут.
- Успех → `AUTH_OK` на stream 0:
  ```
  ver u16, maxPayload u16, windowConn u32, caps u32
  ```
  `maxPayload = 1400`, `windowConn = 16 MiB`, `caps` бит 0 = поддержка URGENT, бит 1 = datagram-потоки, бит 2 = WEB-режим.
- Провал (любая причина) → **никакой ошибки протокола**: сервер продолжает вести себя как обычный веб-сервер. Если в течение 2 с пришёл валидный HTTP-запрос — отвечает сайтом; иначе закрывает соединение по таймауту как idle HTTP keep-alive (не мгновенно).

## 5. Управление потоком

- Окно потока: начальное 4 MiB. Окно соединения: 16 MiB.
- Отправитель обязан не превышать окно; получатель шлёт `WU` при потреблении 25 % окна (не на каждый кадр).
- `WU` с `stream = 0` — окно соединения.
- `URGENT`-кадры не учитываются в pacing/коалесинге, но учитываются в окне.

## 6. Datagram-потоки (UDP-релей, голос)

- Открываются так же (`OPEN`, atyp = цель), но помечаются в `AUTH_OK.caps` поддержкой; в MVP допускается не реализовывать — тогда `caps` бит 1 = 0 и клиент обязан не открывать UDP.
- `DATA` с `MORE=1` — граница датаграммы; потери не переотправляются.

## 7. Таймауты и keepalive

- `PING` раз в 25 с при отсутствии трафика; отсутствие ответа 3 раза → разрыв.
- Idle-таймаут сервера без AUTH: 10 с. С валидным AUTH: 300 с.

## 8. Пакеты Go (контракт, чтобы параллельная разработка не разъехалась)

```go
package proto

const (
    TypeData   = 0x01; TypeAck = 0x02; TypePad = 0x03; TypePing = 0x04
    TypeWU     = 0x05; TypeFin = 0x06; TypeMig = 0x07; TypeAuth = 0x08
    TypeAuthOK = 0x09; TypeClose = 0x0A

    FlagOpen = 0x01; FlagFin = 0x02; FlagMore = 0x04; FlagUrgent = 0x08

    MaxPayload = 1400
)

type Header struct{ Type, Flags uint8; Stream uint16; Length uint16 }

func (h Header) MarshalTo(b []byte)      // пишет 8 байт
func ParseHeader(b []byte) (Header, error)
func ReadFrame(r io.Reader, buf []byte) (Header, []byte, error) // buf >= 8+MaxPayload
func WriteFrame(w io.Writer, h Header, payload []byte) error

// AUTH
func AuthTag(psk, exporter []byte, ver uint16, ts uint64, nonce []byte) [32]byte
func MakeAuth(psk, exporter []byte, now time.Time) ([]byte, error)   // 50 байт
func VerifyAuth(psk, exporter, payload []byte, now time.Time) error  // nil = ок
func AuthPayloadTS(payload []byte) (ts uint64, nonce []byte, ok bool)

// AUTH_OK: 12 байт, big-endian
func MakeAuthOK(maxPayload uint16, windowConn uint32, caps uint32) []byte
func ParseAuthOK(b []byte) (maxPayload uint16, windowConn, caps uint32, err error)

// WU: 6 байт — stream u16 + delta u32 (big-endian)
func WUPayload(stream uint16, delta uint32) []byte

// Caps (биты в AUTH_OK.caps)
const (
    CapUrgent   = 1 << 0  // URGENT-кадры обходят шейпер
    CapDatagram = 1 << 1  // datagram-потоки (MORE/ACK)
    CapWeb      = 1 << 2  // WEB-режим (HTTP/2-инкапсуляция), этап 3
)

// адресный блок §3 — общий кодек клиента и сервера
func EncodeTarget(host, port string) ([]byte, error)
func DecodeTarget(b []byte) (host, port string, err error)
func TargetLen(b []byte) int   // -1 если битый
```

```go
package mux

type Config struct {
    IsClient   bool
    PSK        []byte        // 32 байта
    Exporter   []byte        // 32 байта из TLS
    WindowConn uint32        // 0 => 16 MiB
}

type Session struct{ /* ... */ }

func New(conn io.ReadWriter, cfg Config) (*Session, error) // шлёт/ждёт AUTH, запускает writer-loop
func (s *Session) OpenStream(ctx context.Context, target []byte) (*Stream, error)
func (s *Session) AcceptStream(ctx context.Context) (*Stream, error)
func (s *Session) Close() error
func (s *Session) Done() <-chan struct{}

type Stream struct{ /* ... */ }
func (st *Stream) Read(p []byte) (int, error)
func (st *Stream) Write(p []byte) (int, error)
func (st *Stream) Close() error            // FIN + освобождение
func (st *Stream) SetUrgent(on bool)       // флаг URGENT на исходящие
```

Требования к реализации: zero-alloc в hot path (буферы из `sync.Pool` фиксированных классов), один writer-goroutine на сессию (без мьютекса на каждый кадр), один reader-goroutine, никакого `time.After` в цикле, `context` для отмены.

## 8a. Уточнения, выявленные при реализации (v0.1.1)

1. **Начальные окна не согласуются в handshake** — обе стороны предполагают 4 MiB / 16 MiB, далее только WU. `AUTH_OK.maxPayload` учитывается отправителем. Менять — только версией протокола.
2. **`CLOSE` должен закрывать поток, а не сессию.** Реализация v0.1 закрывает сессию — это дефект, подлежит исправлению в этапе 3 (в MVP не критично: клиент переоткрывает сессию).
3. **ACK** — входящие ACK в MVP игнорируются (datagram-потоков нет).
4. **`MIG`** — не отправляется, входящий игнорируется.
5. Одна очередь исходящих (512 кадров) на данные и управление: теоретический дедлок при забитой очереди и застрявшем `Write`. На практике WU идёт 1 на МиБ.

## 9. Что НЕ входит в MVP

- WEB-режим (HTTP/2-инкапсуляция), миграция сессии, QUIC-путь, паддинг-шейпер, split-tunnel, TUN.
- Мультиендпоинт и health-check.
Это этапы 3–5, контракт для них не фиксируется сейчас.
