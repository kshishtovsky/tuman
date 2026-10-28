package proto

import "testing"

func TestTargetRoundTrip(t *testing.T) {
	for _, hp := range []string{"1.2.3.4:443", "[2001:db8::1]:53", "example.com:8080"} {
		b, err := EncodeTarget(hp)
		if err != nil {
			t.Fatalf("%s: %v", hp, err)
		}
		if n := TargetLen(b); n != len(b) {
			t.Fatalf("%s: TargetLen = %d, len = %d", hp, n, len(b))
		}
		got, err := DecodeTarget(b)
		if err != nil || got != hp {
			t.Fatalf("%s: DecodeTarget = %q, %v", hp, got, err)
		}
	}
}

func TestTargetBad(t *testing.T) {
	for _, hp := range []string{"", "1.2.3.4", "1.2.3.4:", ":80", "1.2.3.4:70000"} {
		if _, err := EncodeTarget(hp); err == nil {
			t.Fatalf("%q: ждали ошибку", hp)
		}
	}
	for _, b := range [][]byte{nil, {9}, {1, 0, 0}, {2, 0, 0, 80}, {2, 40, 'a'}, {3, 1, 2}} {
		if _, err := DecodeTarget(b); err == nil {
			t.Fatalf("%x: ждали ошибку", b)
		}
	}
	// хвост после блока — это уже данные потока, не ошибка
	if hp, err := DecodeTarget([]byte{1, 127, 0, 0, 1, 0, 80, 'x'}); err != nil || hp != "127.0.0.1:80" {
		t.Fatalf("с хвостом: %q, %v", hp, err)
	}
}
