package proto

import (
	"bytes"
	"testing"
	"time"
)

var (
	testPSK = bytes.Repeat([]byte{0x11}, 32)
	testExp = bytes.Repeat([]byte{0x22}, 32)
	now     = time.Unix(1_800_000_000, 0)
)

func TestAuthValid(t *testing.T) {
	p, err := MakeAuth(testPSK, testExp, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != authLen {
		t.Fatalf("payload %d байт, ждали %d", len(p), authLen)
	}
	if err := VerifyAuth(testPSK, testExp, p, now); err != nil {
		t.Fatalf("валидный тег отвергнут: %v", err)
	}
	if err := VerifyAuth(testPSK, testExp, p, now.Add(119*time.Second)); err != nil {
		t.Fatalf("ts в пределах skew отвергнут: %v", err)
	}
}

func TestAuthSkew(t *testing.T) {
	p, _ := MakeAuth(testPSK, testExp, now)
	if err := VerifyAuth(testPSK, testExp, p, now.Add(121*time.Second)); err != ErrAuth {
		t.Fatalf("просроченный ts: %v, ждали ErrAuth", err)
	}
	if err := VerifyAuth(testPSK, testExp, p, now.Add(-121*time.Second)); err != ErrAuth {
		t.Fatalf("ts из будущего: %v, ждали ErrAuth", err)
	}
}

func TestAuthTampered(t *testing.T) {
	p, _ := MakeAuth(testPSK, testExp, now)

	bad := append([]byte(nil), p...)
	bad[20] ^= 0x80
	if err := VerifyAuth(testPSK, testExp, bad, now); err != ErrAuth {
		t.Fatalf("подменённый тег: %v, ждали ErrAuth", err)
	}

	bad = append([]byte(nil), p...)
	bad[12] ^= 0x01
	if err := VerifyAuth(testPSK, testExp, bad, now); err != ErrAuth {
		t.Fatalf("подменённый nonce: %v, ждали ErrAuth", err)
	}

	if err := VerifyAuth(bytes.Repeat([]byte{0x33}, 32), testExp, p, now); err != ErrAuth {
		t.Fatalf("чужой PSK: %v, ждали ErrAuth", err)
	}
	if err := VerifyAuth(testPSK, bytes.Repeat([]byte{0x44}, 32), p, now); err != ErrAuth {
		t.Fatalf("чужой exporter: %v, ждали ErrAuth", err)
	}

	bad = append([]byte(nil), p...)
	bad[1] = 2
	if err := VerifyAuth(testPSK, testExp, bad, now); err != ErrAuth {
		t.Fatalf("чужой ver: %v, ждали ErrAuth", err)
	}

	if err := VerifyAuth(testPSK, testExp, p[:49], now); err != ErrAuth {
		t.Fatalf("короткий payload: %v, ждали ErrAuth", err)
	}
}

func TestAuthTagDeterministic(t *testing.T) {
	a := AuthTag(testPSK, testExp, 1, 42, []byte("12345678"))
	b := AuthTag(testPSK, testExp, 1, 42, []byte("12345678"))
	if a != b {
		t.Fatal("AuthTag недетерминирован")
	}
	c := AuthTag(testPSK, testExp, 1, 43, []byte("12345678"))
	if a == c {
		t.Fatal("AuthTag не зависит от ts")
	}
}

func TestReplay(t *testing.T) {
	p, _ := MakeAuth(testPSK, testExp, now)
	ts, nonce, ok := AuthPayloadTS(p)
	if !ok {
		t.Fatal("AuthPayloadTS")
	}
	c := NewReplayCache()
	if c.Seen(now, ts, nonce) {
		t.Fatal("первый раз Seen = true")
	}
	if !c.Seen(now, ts, nonce) {
		t.Fatal("replay не поймали")
	}
	if !c.Seen(now.Add(time.Second), ts, nonce) {
		t.Fatal("replay не поймали повторно")
	}
	// другой nonce — не replay
	p2, _ := MakeAuth(testPSK, testExp, now)
	ts2, nonce2, _ := AuthPayloadTS(p2)
	if c.Seen(now, ts2, nonce2) {
		t.Fatal("новый nonce посчитан replay")
	}
	// истёк TTL — пара снова принимается
	if c.Seen(now.Add(replayTTL+time.Second), ts, nonce) {
		t.Fatal("после TTL пара не вычищена")
	}
}

func TestReplayCapacity(t *testing.T) {
	c := NewReplayCache()
	for i := 0; i < replayCap+10; i++ {
		var n [8]byte
		n[0] = byte(i)
		n[1] = byte(i >> 8)
		n[2] = byte(i >> 16)
		if c.Seen(now, uint64(i), n[:]) {
			t.Fatalf("ложный replay на %d", i)
		}
	}
	if len(c.m) > replayCap {
		t.Fatalf("%d записей при ёмкости %d", len(c.m), replayCap)
	}
}

func TestAuthOK(t *testing.T) {
	p := MakeAuthOK(MaxPayload, 16<<20, CapUrgent)
	mp, wc, caps, err := ParseAuthOK(p)
	if err != nil || mp != MaxPayload || wc != 16<<20 || caps != CapUrgent {
		t.Fatalf("ParseAuthOK = %d %d %d %v", mp, wc, caps, err)
	}
	if _, _, _, err := ParseAuthOK(p[:11]); err == nil {
		t.Fatal("короткий AUTH_OK принят")
	}
}
