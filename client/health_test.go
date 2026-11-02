package client

import (
	"strings"
	"testing"
	"time"
)

func TestHealthCooldown(t *testing.T) {
	h := newHealth(2, 30*time.Second)
	now := time.Unix(1000, 0)
	h.now = func() time.Time { return now }

	h.ok(0, 12*time.Millisecond)
	if s := h.String(); !strings.Contains(s, "ep=0 ok=1 fail=0") {
		t.Fatalf("health: %s", s)
	}
	if ok, _ := h.usable(0); !ok {
		t.Fatal("здоровый ендпоинт в паузе")
	}
	// сбой ендпоинта виден сразу: первый промах эпизода даёт паузу...
	h.fail(0)
	ok, rem := h.usable(0)
	if ok || rem != 30*time.Second {
		t.Fatalf("пауза после промаха: ok=%v rem=%v", ok, rem)
	}
	// ...а пачка промахов от остальных слотов того же эпизода её не удваивает
	h.fail(0)
	if _, rem := h.usable(0); rem != 30*time.Second {
		t.Fatalf("пачка промахов удвоила паузу: %v", rem)
	}
	if got := h.next(0); got != 1 {
		t.Fatalf("next(0)=%d, ждали 1 (ep=0 в паузе)", got)
	}
	if s := h.String(); !strings.Contains(s, "cool=30s") {
		t.Fatalf("health: %s", s)
	}
	now = now.Add(30 * time.Second)
	if ok, _ := h.usable(0); !ok {
		t.Fatal("пауза не истекла через 30 с")
	}
	h.fail(0)
	if _, rem := h.usable(0); rem != 60*time.Second {
		t.Fatalf("вторая пауза %v, ждали 1m", rem)
	}
	for i := 0; i < 10; i++ {
		now = now.Add(10 * time.Minute)
		h.usable(0) // пауза истекла — следующий промах это новый эпизод
		h.fail(0)
	}
	if _, rem := h.usable(0); rem != 60*time.Second {
		t.Fatalf("потолок паузы %v, ждали 1m", rem)
	}
	h.ok(0, time.Millisecond)
	if ok, _ := h.usable(0); !ok {
		t.Fatal("после успеха пауза осталась")
	}
	if s := h.String(); !strings.Contains(s, "ep=0 ok=2 fail=13") {
		t.Fatalf("счётчики: %s", s)
	}
}

// Все в паузе — берём того, кто отпустит раньше; один ендпоинт — его же.
func TestHealthNextEarliest(t *testing.T) {
	h := newHealth(3, time.Minute)
	now := time.Unix(2000, 0)
	h.now = func() time.Time { return now }
	for _, i := range []int{1, 0, 2} {
		h.fail(i)
		h.fail(i)
		now = now.Add(10 * time.Second)
	}
	for from := 0; from < 3; from++ {
		if got := h.next(from); got != 1 {
			t.Fatalf("next(%d)=%d, ждали 1 (его пауза кончается раньше)", from, got)
		}
	}
	one := newHealth(1, time.Minute)
	one.fail(0)
	one.fail(0)
	if got := one.next(0); got != 0 {
		t.Fatalf("next(0) на единственном ендпоинте = %d", got)
	}
}
