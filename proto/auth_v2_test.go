package proto

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// --- v1: исправления аудита ---

// Окно свежести не обходится переполнением: ts = now ± 2^63 раньше проходил
// проверку, потому что |d| считался как d = -d и оставался отрицательным.
func TestAuthSkewOverflow(t *testing.T) {
	for _, name := range []string{"future", "past"} {
		p, err := MakeAuth(testPSK, testExp, now)
		if err != nil {
			t.Fatal(err)
		}
		delta := uint64(1 << 63)
		var ts uint64
		if name == "future" {
			ts = uint64(now.Unix()) + delta
		} else {
			ts = uint64(now.Unix()) - delta
		}
		binaryPutTs(p, ts)
		// тег пересчитываем, иначе отказ придёт по тегу, а не по окну
		tag := AuthTag(testPSK, testExp, AuthVersion, ts, p[10:18])
		copy(p[18:], tag[:])
		if err := VerifyAuth(testPSK, testExp, p, now); err != ErrAuth {
			t.Fatalf("%s: ts=now±2^63 принят (%v), ждали ErrAuth", name, err)
		}
	}
}

// Границы окна: 120 c — ещё можно, 121 — уже нет.
func TestAuthSkewBounds(t *testing.T) {
	p, _ := MakeAuth(testPSK, testExp, now)
	if err := VerifyAuth(testPSK, testExp, p, now.Add(120*time.Second)); err != nil {
		t.Fatalf("ts+120 отвергнут: %v", err)
	}
	if err := VerifyAuth(testPSK, testExp, p, now.Add(-120*time.Second)); err != nil {
		t.Fatalf("ts-120 отвергнут: %v", err)
	}
}

// AuthTag требует ровно 32 байта ключа и exporter: иначе ошибка, а не тихое усечение.
func TestAuthLengths(t *testing.T) {
	short := bytes.Repeat([]byte{0x11}, 31)
	long := bytes.Repeat([]byte{0x11}, 33)
	if _, err := MakeAuth(short, testExp, now); err != ErrAuth {
		t.Fatalf("psk 31 байт: %v, ждали ErrAuth", err)
	}
	if _, err := MakeAuth(testPSK, long, now); err != ErrAuth {
		t.Fatalf("exporter 33 байта: %v, ждали ErrAuth", err)
	}
	p, _ := MakeAuth(testPSK, testExp, now)
	if err := VerifyAuth(long, testExp, p, now); err != ErrAuth {
		t.Fatalf("VerifyAuth с psk 33: %v, ждали ErrAuth", err)
	}
	if err := VerifyAuth(testPSK, long, p, now); err != ErrAuth {
		t.Fatalf("VerifyAuth с exporter 33: %v, ждали ErrAuth", err)
	}
}

// Один кэш на сервер: повтор (ts,nonce) отклоняется, кэш переживает горутины.
func TestReplaySharedAcrossSessions(t *testing.T) {
	c := NewReplayCacheWith(time.Minute, 128)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ts := uint64(now.Unix())
	if c.Seen(now, ts, nonce) {
		t.Fatal("первый AUTH посчитан реплеем")
	}
	if !c.Seen(now, ts, nonce) {
		t.Fatal("повтор (ts,nonce) через секунду принят — реплей не ловится")
	}
}

func TestReplayCapacityAndTTL(t *testing.T) {
	c := NewReplayCacheWith(time.Minute, 4)
	for i := 0; i < 100; i++ {
		n := []byte{0, 0, 0, 0, 0, 0, 0, byte(i)}
		if c.Seen(now, uint64(i), n) {
			t.Fatalf("итерация %d: свежий nonce посчитан реплеем", i)
		}
	}
	if len(c.m) > 4 {
		t.Fatalf("кэш вырос до %d при ёмкости 4", len(c.m))
	}
	// TTL: запись старше ttl вытесняется и тот же nonce снова проходит
	c2 := NewReplayCacheWith(time.Minute, 8)
	n := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	if c2.Seen(now, 1, n) || !c2.Seen(now, 1, n) {
		t.Fatal("базовая работа кэша сломана")
	}
	if c2.Seen(now.Add(2*time.Minute), 2, n) {
		t.Fatal("запись не вытеснена по TTL")
	}
}

// Кэш обязан быть потокобезопасным: гоняем под -race.
func TestReplayConcurrent(t *testing.T) {
	c := NewReplayCache()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				n := []byte{byte(g), 0, 0, 0, 0, 0, 0, byte(i)}
				c.Seen(now, uint64(i), n)
			}
		}(g)
	}
	wg.Wait()
}

func binaryPutTs(p []byte, ts uint64) {
	for i := 0; i < 8; i++ {
		p[2+i] = byte(ts >> (56 - 8*i))
	}
}

// --- v2: X25519 + MAC ---

func TestAuthV2Roundtrip(t *testing.T) {
	ck, err := NewEphemeralKeyV2()
	if err != nil {
		t.Fatal(err)
	}
	cliPub := PublicKeyV2(ck)
	p, err := MakeAuthV2(testPSK, cliPub, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != authV2Len {
		t.Fatalf("AUTH v2 %d байт, ждали %d", len(p), authV2Len)
	}
	ts, nonce, gotPub, err := VerifyAuthV2(testPSK, p, now)
	if err != nil {
		t.Fatalf("валидный AUTH v2 отвергнут: %v", err)
	}
	if ts != uint64(now.Unix()) || !bytes.Equal(gotPub, cliPub) || len(nonce) != NonceLen {
		t.Fatalf("разбор неверен: ts=%d pub=%x nonce=%d", ts, gotPub, len(nonce))
	}
}

func TestAuthV2Rejects(t *testing.T) {
	ck, _ := NewEphemeralKeyV2()
	p, _ := MakeAuthV2(testPSK, PublicKeyV2(ck), now)

	// подмена любого поля -> тег не сходится
	for _, i := range []int{1, 3, 11, 20, 60} {
		bad := append([]byte(nil), p...)
		bad[i] ^= 0x01
		if _, _, _, err := VerifyAuthV2(testPSK, bad, now); err != ErrAuthV2 {
			t.Fatalf("подмена байта %d принята (%v)", i, err)
		}
	}
	// чужой PSK
	if _, _, _, err := VerifyAuthV2(bytes.Repeat([]byte{0x33}, 32), p, now); err != ErrAuthV2 {
		t.Fatalf("чужой PSK принят: %v", err)
	}
	// окно, в том числе переполнение
	if _, _, _, err := VerifyAuthV2(testPSK, p, now.Add(121*time.Second)); err != ErrAuthV2 {
		t.Fatalf("просроченный AUTH v2 принят")
	}
	// неверная версия
	bad := append([]byte(nil), p...)
	bad[0], bad[1] = 0, 1
	if _, _, _, err := VerifyAuthV2(testPSK, bad, now); err != ErrAuthV2 {
		t.Fatalf("ver=1 на месте v2 принят")
	}
}

// Главное: AUTH_OK без валидного MAC больше не проходит.
func TestAuthOKV2RequiresMAC(t *testing.T) {
	ck, _ := NewEphemeralKeyV2()
	sk, _ := NewEphemeralKeyV2()
	cliPub, srvPub := PublicKeyV2(ck), PublicKeyV2(sk)

	auth, _ := MakeAuthV2(testPSK, cliPub, now)
	ts, nonce, _, err := VerifyAuthV2(testPSK, auth, now)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := MakeAuthOKV2(testPSK, cliPub, srvPub, nonce, ts)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthOKV2(testPSK, ok, cliPub, nonce, ts); err != nil {
		t.Fatalf("валидный AUTH_OK v2 отвергнут: %v", err)
	}

	// подмена nonce-эха
	bad := append([]byte(nil), ok...)
	bad[2] ^= 0x01
	if err := VerifyAuthOKV2(testPSK, bad, cliPub, nonce, ts); err == nil {
		t.Fatal("AUTH_OK с подменённым nonce принят")
	}
	// подмена serverPub
	bad = append([]byte(nil), ok...)
	bad[20] ^= 0x01
	if err := VerifyAuthOKV2(testPSK, bad, cliPub, nonce, ts); err == nil {
		t.Fatal("AUTH_OK с подменённым serverPub принят")
	}
	// подмена тега
	bad = append([]byte(nil), ok...)
	bad[60] ^= 0x01
	if err := VerifyAuthOKV2(testPSK, bad, cliPub, nonce, ts); err == nil {
		t.Fatal("AUTH_OK с подменённым тегом принят")
	}
	// сервер без PSK
	if err := VerifyAuthOKV2(bytes.Repeat([]byte{0x44}, 32), ok, cliPub, nonce, ts); err == nil {
		t.Fatal("AUTH_OK от сервера без PSK принят")
	}
	// пустой/короткий AUTH_OK (как в v1, 12 байт) не проходит
	if err := VerifyAuthOKV2(testPSK, MakeAuthOK(MaxPayload, 32<<20, CapUrgent), cliPub, nonce, ts); err == nil {
		t.Fatal("v1-подобный AUTH_OK без MAC принят")
	}
}

func TestSessionKeyV2(t *testing.T) {
	ck, _ := NewEphemeralKeyV2()
	sk, _ := NewEphemeralKeyV2()

	kc, err := SessionKeyV2(testPSK, ck, PublicKeyV2(sk))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := SessionKeyV2(testPSK, sk, PublicKeyV2(ck))
	if err != nil {
		t.Fatal(err)
	}
	if kc != ks {
		t.Fatal("сессионные ключи сторон не совпали")
	}
	// разные пары -> разные ключи
	ck2, _ := NewEphemeralKeyV2()
	k2, _ := SessionKeyV2(testPSK, ck2, PublicKeyV2(sk))
	if k2 == kc {
		t.Fatal("ключ не зависит от пары")
	}
	// другой PSK -> другой ключ
	k3, _ := SessionKeyV2(bytes.Repeat([]byte{0x55}, 32), ck, PublicKeyV2(sk))
	if k3 == kc {
		t.Fatal("ключ не зависит от PSK")
	}
	// мусор вместо публичного ключа
	if _, err := SessionKeyV2(testPSK, ck, make([]byte, 8)); err == nil {
		t.Fatal("короткий публичный ключ принят")
	}
	// нулевой публичный ключ (low-order point) — X25519 обязан отказать
	if _, err := SessionKeyV2(testPSK, ck, make([]byte, 32)); err == nil {
		t.Fatal("нулевой публичный ключ принят: low-order point")
	}
}

// nonce должен быть случайным: два AUTH подряд не совпадают.
func TestAuthV2NonceUnique(t *testing.T) {
	ck, _ := NewEphemeralKeyV2()
	pub := PublicKeyV2(ck)
	a, _ := MakeAuthV2(testPSK, pub, now)
	b, _ := MakeAuthV2(testPSK, pub, now)
	if bytes.Equal(a[10:18], b[10:18]) {
		t.Fatal("nonce повторился")
	}
	var z [8]byte
	if _, err := rand.Read(z[:]); err != nil {
		t.Fatal(err)
	}
}
