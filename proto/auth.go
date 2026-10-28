package proto

import (
	"container/list"
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
func AuthTag(psk, exporter []byte, ver uint16, ts uint64, nonce []byte) [32]byte {
	if len(exporter) > 32 {
		exporter = exporter[:32]
	}
	var msg [9 + 32 + 2 + 8 + 8]byte
	var nb [8]byte
	copy(nb[:], nonce)
	n := copy(msg[:], authLabel)
	n += copy(msg[n:], exporter)
	binary.BigEndian.PutUint16(msg[n:], ver)
	binary.BigEndian.PutUint64(msg[n+2:], ts)
	copy(msg[n+10:], nb[:])

	m := hmac.New(sha256.New, psk)
	m.Write(msg[:n+18])
	var tag [32]byte
	copy(tag[:], m.Sum(nil))
	return tag
}

// MakeAuth собирает 50-байтовый payload AUTH с текущим ts и случайным nonce.
func MakeAuth(psk, exporter []byte, now time.Time) ([]byte, error) {
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
	if len(payload) != authLen {
		return ErrAuth
	}
	if binary.BigEndian.Uint16(payload[0:]) != AuthVersion {
		return ErrAuth
	}
	ts := binary.BigEndian.Uint64(payload[2:])
	d := now.Unix() - int64(ts)
	if d < 0 {
		d = -d
	}
	if d > AuthSkew {
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
type ReplayCache struct {
	mu sync.Mutex
	ll *list.List
	m  map[replayKey]*list.Element
}

// NewReplayCache — пустой кэш; нулевое значение непригодно.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{ll: list.New(), m: make(map[replayKey]*list.Element, 64)}
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
	// вытесняем с головы: просроченные и лишние (порядок вставки)
	for f := c.ll.Front(); f != nil; f = c.ll.Front() {
		e := f.Value.(replayEntry)
		if len(c.m) < replayCap && now.Sub(e.at) < replayTTL {
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
