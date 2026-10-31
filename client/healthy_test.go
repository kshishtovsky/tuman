package client

import (
	"testing"
	"time"
)

// Пустой пул не должен выглядеть здоровым: приложение по Healthy() решает,
// показывать ли канал живым, и не должно ждать.
func TestHealthyEmptyPool(t *testing.T) {
	c, err := New(Config{
		Servers: []Endpoint{{Addr: "127.0.0.1:1"}},
		PSK:     make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan bool, 1)
	go func() { done <- c.Healthy() }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Healthy() = true on an empty pool")
		}
	case <-time.After(time.Second):
		t.Fatal("Healthy() blocked")
	}
}
