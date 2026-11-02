package client

// Регресс аудита: когда сессия не поднимается, openWith отдавал голый
// context.DeadlineExceeded. По нему нельзя отличить мёртвый сервер от
// исчерпанного лимита соединений (tmns закрывает 31-е соединение с IP молча)
// и от чужого PSK — на Android лога нет вовсе. Теперь причина слоя доезжает.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestDialFailureReportsCause(t *testing.T) {
	addr := silentTLSDrop(t) // TLS доводится и рвётся до AUTH
	c, err := New(Config{
		Servers: []Endpoint{{Addr: addr}},
		PSK:     testPSK, SNI: "localhost", Insecure: true, Conns: 1,
		Cooldown: 50 * time.Millisecond,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	_, err = c.DialContext(ctx, "tcp", "1.1.1.1:443")
	if err == nil {
		t.Fatal("dial прошёл, хотя сервер рвёт соединение после TLS")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ждали обёрнутый DeadlineExceeded, получили %v", err)
	}
	if !strings.HasPrefix(err.Error(), "tmn: сессия не поднялась (") {
		t.Fatalf("причина слоя потерялась: %v", err)
	}
}
