package client

// Регресс аудита (Т04): при провале mux.handshake шейпер оставался жить.
// shaper.New при profile != off сразу поднимает горутину отделки кадров, а на
// пути ошибки закрывали только TLS-соединение — горутина и ссылка на мёртвый
// коннект висели до конца процесса. Здесь сервер доводит TLS и сразу рвёт
// соединение: mux.New падает, и утёкшие горутины считаются.

import (
	"crypto/tls"
	"log/slog"
	"runtime"
	"testing"
	"time"
)

// silentTLSDrop принимает TCP, доводит TLS и закрывает: AUTH уже не состоится.
func silentTLSDrop(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				_ = tc.Handshake()
				tc.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestFailedDialDoesNotLeakShaper(t *testing.T) {
	addr := silentTLSDrop(t)
	c, err := New(Config{
		Servers:  []Endpoint{{Addr: addr}},
		PSK:      testPSK,
		SNI:      "localhost",
		Insecure: true,
		Conns:    1,
		Profile:  "browse", // именно профиль поднимает горутину шейпера
		Cooldown: 50 * time.Millisecond,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	base := runtime.NumGoroutine() // до попыток: утёкшие горутины уже были бы в базе

	// Шесть попыток установления: каждая проходит TLS и падает на AUTH.
	for i := 0; i < 6; i++ {
		if _, err := c.dial(0); err == nil {
			t.Fatal("dial прошёл, хотя сервер рвёт соединение после TLS")
		}
	}

	// Горутина шейпера на каждом провале давала +6 к счётчику навсегда.
	// Ждём, пока рантайм уберёт свои временные горутины, и требуем возврата
	// к базовой линии (запас 2 — за счёт сетевого поллера).
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		if n := runtime.NumGoroutine(); n <= base+2 {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("горутин %d при базе %d: шейпер не закрылся после ошибки dial\n%s",
				runtime.NumGoroutine(), base, buf)
		}
	}
}
