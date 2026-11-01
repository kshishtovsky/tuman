package proto

import (
	"container/list"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	AuthVersion = 1
	authLen     = 50
	AuthSkew    = 120 // секунд, §4

	// KeyLen — длина PSK и любого ключевого материала протокола.
	KeyLen = 32

	// caps в AUTH_OK
	CapUrgent   = 1 << 0
	CapDatagram = 1 << 1
	CapWeb      = 1 << 2
)

var (
	ErrAuth   = errors.New("proto: AUTH отклонён")
	ErrAuthOK = errors.New("proto: AUTH_OK битый")
	authLabel = []byte("TMN1-AUTH")
)

// AuthTag = HMAC-SHA256(psk, "TMN1-AUTH" || exporter || ver || ts || nonce)[32].
// ver и ts — big-endian, как в заголовке кадра.
// Контракт: len(psk) == len(exporter) == KeyLen. Длины проверяют MakeAuth и
// VerifyAuth; сам AuthTag копирует в 32-байтовый слот сообщения и ошибку не
// возвращает — вызывать его напрямую с другими длинами нельзя.
func AuthTag(psk, exporter []byte, ver uint16, ts uint64, nonce []byte) [32]byte {
	var msg [9 + KeyLen + 2 + 8 + 8]byte
	var nb [8]byte
	copy(nb[:], nonce)
	n := copy(msg[:], authLabel)
	n += copy(msg[n:], exporter[:min(len(exporter), KeyLen)])
	binary.BigEndian.PutUint16(msg[n:], ver)
	binary.BigEndian.PutUint64(msg[n+2:], ts)
	copy(msg[n+10:], nb[:])

	m := hmac.New(sha256.New, psk)
	m.Write(msg[:n+18])
	var tag [32]byte
	copy(tag[:], m.Sum(nil))
	return tag
}

// skewOK — |now - ts| <= AuthSkew без знаковой арифметики: разность двух uint64
// определена по модулю 2^64, поэтому ts = now+2^63 даёт разницу 2^63 > AuthSkew,
// а не MinInt64 с последующим -d (старый вариант такую метку пропускал).
func skewOK(now time.Time, ts uint64) bool {
	n := uint64(now.Unix())
	d := n - ts
	if ts > n {
		d = ts - n
	}
	return d <= AuthSkew
}

// MakeAuth собирает 50-байтовый payload AUTH с текущим ts и случайным nonce.
func MakeAuth(psk, exporter []byte, now time.Time) ([]byte, error) {
	if len(psk) != KeyLen || len(exporter) != KeyLen {
		return nil, ErrAuth
	}
	b := make([]byte, authLen)
	binary.BigEndian.PutUint16(b[0:], AuthVersion)
	ts := uint64(now.Unix())
	binary.BigEndian.PutUint64(b[2:], ts)
	if _, err := rand.Read(b[10:18]); err != nil {
		return nil, err
	}
	tag := AuthTag(psk, exporter, AuthVersion, ts, b[10:18])
	copy(b[18:], tag[:])
	return b, nil
}

// VerifyAuth проверяет ver, |now-ts| <= 120 c и тег (constant-time). Replay — ReplayCache.
func VerifyAuth(psk, exporter, payload []byte, now time.Time) error {
	if len(psk) != KeyLen || len(exporter) != KeyLen {
		return ErrAuth
	}
	if len(payload) != authLen {
		return ErrAuth
	}
	if binary.BigEndian.Uint16(payload[0:]) != AuthVersion {
		return ErrAuth
	}
	ts := binary.BigEndian.Uint64(payload[2:])
	if !skewOK(now, ts) {
		return ErrAuth
	}
	want := AuthTag(psk, exporter, AuthVersion, ts, payload[10:18])
	if !hmac.Equal(want[:], payload[18:50]) {
		return ErrAuth
	}
	return nil
}

// AuthPayloadTS разбирает ts и nonce из payload AUTH (уже проверенного VerifyAuth).
func AuthPayloadTS(payload []byte) (ts uint64, nonce []byte, ok bool) {
	if len(payload) != authLen {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(payload[2:]), payload[10:18], true
}

// AUTH_OK: ver u16, maxPayload u16, windowConn u32, caps u32.
func MakeAuthOK(maxPayload uint16, windowConn, caps uint32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], AuthVersion)
	binary.BigEndian.PutUint16(b[2:], maxPayload)
	binary.BigEndian.PutUint32(b[4:], windowConn)
	binary.BigEndian.PutUint32(b[8:], caps)
	return b
}

func ParseAuthOK(p []byte) (maxPayload uint16, windowConn, caps uint32, err error) {
	if len(p) != 12 || binary.BigEndian.Uint16(p[0:]) != AuthVersion {
		return 0, 0, 0, ErrAuthOK
	}
	return binary.BigEndian.Uint16(p[2:]), binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint32(p[8:]), nil
}

const (
	replayTTL = 5 * time.Minute
	replayCap = 10000
)

type replayKey struct {
	ts    uint64
	nonce [8]byte
}

type replayEntry struct {
	k  replayKey
	at time.Time
}

// ReplayCache — LRU на (ts, nonce) с TTL 5 мин и ёмкостью 10000 (§4).
// Безопасен для конкурентного использования: живёт столько же, сколько сервер,
// и передаётся всем сессиям. Кэш на одну сессию бесполезен — AUTH в сессии
// бывает ровно один раз, повторить его негде.
type ReplayCache struct {
	mu  sync.Mutex
	ll  *list.List
	m   map[replayKey]*list.Element
	ttl time.Duration
	cap int
}

// NewReplayCache — кэш с параметрами по умолчанию (5 мин, 10000).
func NewReplayCache() *ReplayCache {
	return NewReplayCacheWith(replayTTL, replayCap)
}

// NewReplayCacheWith — кэш с явными TTL и ёмкостью; <= 0 означает дефолт.
func NewReplayCacheWith(ttl time.Duration, capacity int) *ReplayCache {
	if ttl <= 0 {
		ttl = replayTTL
	}
	if capacity <= 0 {
		capacity = replayCap
	}
	return &ReplayCache{ll: list.New(), m: make(map[replayKey]*list.Element, 64), ttl: ttl, cap: capacity}
}

// Seen сообщает, что (ts, nonce) уже видели, и запоминает пару.
func (c *ReplayCache) Seen(now time.Time, ts uint64, nonce []byte) bool {
	if len(nonce) < 8 {
		return true
	}
	var k replayKey
	k.ts = ts
	copy(k.nonce[:], nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ll == nil { // нулевое значение: всё считаем реплеем, паниковать незачем
		return true
	}
	// вытесняем с головы: просроченные и лишние (порядок вставки)
	for f := c.ll.Front(); f != nil; f = c.ll.Front() {
		e := f.Value.(replayEntry)
		if len(c.m) < c.cap && now.Sub(e.at) < c.ttl {
			break
		}
		c.ll.Remove(f)
		delete(c.m, e.k)
	}
	if e, ok := c.m[k]; ok {
		c.ll.MoveToBack(e)
		return true
	}
	c.m[k] = c.ll.PushBack(replayEntry{k: k, at: now})
	return false
}

// --- AUTH v2: X25519 + MAC в обе стороны (docs/13-plan-v2.md §3) ---
//
// Зачем: в v1 сервер доказывает знание PSK только самим фактом AUTH_OK, поэтому
// MITM с доверенным клиенту сертификатом выдаёт себя за сервер. В v2 сервер
// обязан прислать MAC, клиент его проверяет, а привязка к соединению идёт через
// ECDH, а не через TLS-exporter: exporter недоступен под uTLS (браузерные
// ClientHello включают renegotiation_info, см. 12-security-audit.md §5).

const (
	// AuthVersionV2 — версия AUTH с X25519 и MAC в AUTH_OK.
	AuthVersionV2 = 2
	// PubKeyLen — длина публичного ключа X25519.
	PubKeyLen = KeyLen
	// NonceLen — длина nonce в AUTH/AUTH_OK.
	NonceLen = 8

	authV2Len   = 2 + 8 + NonceLen + PubKeyLen + 32 // 82
	authOKV2Len = 2 + NonceLen + PubKeyLen + 32     // 74

	// AuthV2Len и AuthOKV2Len — длины кадров на проводе: по ним сервер
	// отличает AUTH v2 от v1 без отдельного согласования версии.
	AuthV2Len   = authV2Len
	AuthOKV2Len = authOKV2Len
)

var (
	ErrAuthV2     = errors.New("proto: AUTH v2 отклонён")
	authV2Label   = []byte("TMN1-AUTH-V2")
	authOKV2Label = []byte("TMN1-AUTH-OK-V2")
	sessionV2Info = "TMN1-SESSION-V2"
)

// NewEphemeralKeyV2 — эфемерная пара X25519 на одну сессию.
func NewEphemeralKeyV2() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// PublicKeyV2 — 32 байта публичного ключа для провода.
func PublicKeyV2(k *ecdh.PrivateKey) []byte { return k.PublicKey().Bytes() }

// MakeAuthV2 собирает 82-байтовый AUTH v2:
// ver u16 | ts u64 | nonce 8 | clientPub 32 | tag 32,
// tag = HMAC-SHA256(psk, "TMN1-AUTH-V2" ‖ ver ‖ ts ‖ nonce ‖ clientPub).
func MakeAuthV2(psk, clientPub []byte, now time.Time) ([]byte, error) {
	return makeAuthV2At(psk, clientPub, now, rand.Read)
}

// makeAuthV2At — шов для детерминированного nonce в тестах.
func makeAuthV2At(psk, clientPub []byte, now time.Time, rnd func([]byte) (int, error)) ([]byte, error) {
	if len(psk) != KeyLen || len(clientPub) != PubKeyLen {
		return nil, ErrAuthV2
	}
	b := make([]byte, authV2Len)
	binary.BigEndian.PutUint16(b[0:], AuthVersionV2)
	binary.BigEndian.PutUint64(b[2:], uint64(now.Unix()))
	if _, err := rnd(b[10:18]); err != nil {
		return nil, err
	}
	copy(b[18:50], clientPub)
	tag := authV2Tag(psk, b[0:2], b[2:10], b[10:18], b[18:50])
	copy(b[50:], tag[:])
	return b, nil
}

// VerifyAuthV2 проверяет ver=2, окно ts и тег (constant-time) и возвращает
// разобранные ts, nonce и clientPub (копии — payload можно освобождать).
func VerifyAuthV2(psk, payload []byte, now time.Time) (ts uint64, nonce, clientPub []byte, err error) {
	if len(psk) != KeyLen || len(payload) != authV2Len {
		return 0, nil, nil, ErrAuthV2
	}
	if binary.BigEndian.Uint16(payload[0:]) != AuthVersionV2 {
		return 0, nil, nil, ErrAuthV2
	}
	ts = binary.BigEndian.Uint64(payload[2:])
	if !skewOK(now, ts) {
		return 0, nil, nil, ErrAuthV2
	}
	want := authV2Tag(psk, payload[0:2], payload[2:10], payload[10:18], payload[18:50])
	if !hmac.Equal(want[:], payload[50:82]) {
		return 0, nil, nil, ErrAuthV2
	}
	nonce = append([]byte(nil), payload[10:18]...)
	clientPub = append([]byte(nil), payload[18:50]...)
	return ts, nonce, clientPub, nil
}

// authV2Tag — HMAC по фиксированной раскладке: варьируемых длин нет, поэтому
// усечение/склейка полей невозможны.
func authV2Tag(psk, ver, ts, nonce, pub []byte) [32]byte {
	m := hmac.New(sha256.New, psk)
	m.Write(authV2Label)
	m.Write(ver)
	m.Write(ts)
	m.Write(nonce)
	m.Write(pub)
	var tag [32]byte
	copy(tag[:], m.Sum(nil))
	return tag
}

// MakeAuthOKV2 собирает 74-байтовый AUTH_OK v2:
// ver u16 | nonce 8 (эхо из AUTH) | serverPub 32 | tag 32,
// tag = HMAC-SHA256(psk, "TMN1-AUTH-OK-V2" ‖ clientPub ‖ serverPub ‖ ts ‖ nonce).
// Именно этот MAC не даёт MITM выдать себя за сервер.
func MakeAuthOKV2(psk, clientPub, serverPub, nonce []byte, ts uint64) ([]byte, error) {
	if len(psk) != KeyLen || len(clientPub) != PubKeyLen || len(serverPub) != PubKeyLen || len(nonce) != NonceLen {
		return nil, ErrAuthV2
	}
	b := make([]byte, authOKV2Len)
	binary.BigEndian.PutUint16(b[0:], AuthVersionV2)
	copy(b[2:10], nonce)
	copy(b[10:42], serverPub)
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], ts)
	m := hmac.New(sha256.New, psk)
	m.Write(authOKV2Label)
	m.Write(clientPub)
	m.Write(serverPub)
	m.Write(tsb[:])
	m.Write(nonce)
	copy(b[42:], m.Sum(nil))
	return b, nil
}

// VerifyAuthOKV2 проверяет AUTH_OK v2 против того, что клиент сам отправил в AUTH
// (clientPub, ts, nonce). Несовпадение nonce-эха или тега — ErrAuthV2.
func VerifyAuthOKV2(psk, payload, clientPub, nonce []byte, ts uint64) error {
	if len(psk) != KeyLen || len(payload) != authOKV2Len || len(clientPub) != PubKeyLen || len(nonce) != NonceLen {
		return ErrAuthV2
	}
	if binary.BigEndian.Uint16(payload[0:]) != AuthVersionV2 {
		return ErrAuthV2
	}
	if !hmac.Equal(payload[2:10], nonce) {
		return ErrAuthV2
	}
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], ts)
	m := hmac.New(sha256.New, psk)
	m.Write(authOKV2Label)
	m.Write(clientPub)
	m.Write(payload[10:42])
	m.Write(tsb[:])
	m.Write(nonce)
	if !hmac.Equal(m.Sum(nil), payload[42:74]) {
		return ErrAuthV2
	}
	return nil
}

// SessionKeyV2 — сессионный ключ: X25519(свой приватный, публичный пира) →
// HKDF-SHA256(salt=psk, info="TMN1-SESSION-V2") → 32 байта.
// Знают только двое участников — это и есть привязка AUTH к соединению.
func SessionKeyV2(psk []byte, priv *ecdh.PrivateKey, peerPub []byte) ([32]byte, error) {
	var out [32]byte
	if len(psk) != KeyLen || priv == nil || len(peerPub) != PubKeyLen {
		return out, ErrAuthV2
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return out, ErrAuthV2
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return out, ErrAuthV2 // low-order point: X25519 отказывает
	}
	k, err := hkdf.Key(sha256.New, shared, psk, sessionV2Info, KeyLen)
	if err != nil {
		return out, ErrAuthV2
	}
	copy(out[:], k)
	return out, nil
}
