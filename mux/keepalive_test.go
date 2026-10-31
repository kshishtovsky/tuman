package mux

// Детект мёртвой сессии: клиент должен уметь задать свой ритм PING.
// Дефолт 25 s x 3 (75 s) хорош для десктопа, но телефон после Doze минуту
// считает канал живым; Rupas ставит 10 s x 2 (20 s).

import (
	"testing"
	"time"
)

func TestKeepaliveDefaults(t *testing.T) {
	every, miss := Config{}.keepalive()
	if every != 25*time.Second || miss != 3 {
		t.Fatalf("defaults: got %v x %d, want 25s x 3", every, miss)
	}
}

func TestKeepaliveOverride(t *testing.T) {
	every, miss := Config{PingEvery: 10 * time.Second, PingMiss: 2}.keepalive()
	if every != 10*time.Second || miss != 2 {
		t.Fatalf("override: got %v x %d, want 10s x 2", every, miss)
	}
}

func TestKeepalivePartialOverride(t *testing.T) {
	// Один заданный параметр не должен тянуть за собой дефолт второго.
	every, miss := Config{PingMiss: 5}.keepalive()
	if every != 25*time.Second || miss != 5 {
		t.Fatalf("partial: got %v x %d, want 25s x 5", every, miss)
	}
}
