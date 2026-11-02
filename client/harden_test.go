package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// newStalledEP — тестовый сервер, который доводит TLS и mux до конца, принимает
// поток и НЕ читает его: окно потока не возвращается, Write клиента встаёт.
func newStalledEP(t *testing.T) *testEP {
	t.Helper()
	e := newTestEP(t)
	e.mu.Lock()
	e.stall = true
	e.mu.Unlock()
	return e
}

// floodEP — сервер, который доводит TLS до конца и сразу рвёт соединение:
// так выглядит «принял и бросил». Считает завершённые рукопожатия.
func floodEP(t *testing.T) (addr string, count func() int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	hs := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err == nil {
					mu.Lock()
					hs++
					mu.Unlock()
				}
				tc.Close()
			}()
		}
	}()
	return ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return hs
	}
}

// Сервер принимает TLS и рвёт: раньше сессия считалась живой и шёл Reset(0) —
// 6189 рукопожатий за 3 с. Теперь смерть через aliveMin — это промах ендпоинта.
func TestShortLivedSessionsNoFlood(t *testing.T) {
	addr, count := floodEP(t)
	c := newTestClient(t, 2, 0, addr)
	// пул стартует на первом DialContext; сессии не будет — ждать нечего
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c.DialContext(ctx, "tcp", addr)

	const watch = 4 * time.Second
	time.Sleep(watch)
	if n := count(); n == 0 {
		t.Fatal("сервер не принял ни одного рукопожатия — тест ничего не проверил")
	} else if n > 2*int(watch/time.Second)+4 { // ~2 рукопожатия в секунду на ендпоинт
		t.Fatalf("за %v рукопожатий: %d (флуд: 6189 за 3 с)", watch, n)
	} else {
		t.Logf("за %v рукопожатий: %d", watch, count())
	}
}

// Блип 1.5 с: после возврата сервера пул обязан подняться за 3 с (NFR-12).
func TestBlipRestore(t *testing.T) {
	ep := newTestEP(t)
	c := newTestClient(t, 2, 0, ep.addr)
	echoRoundtrip(t, c, ep.addr, 1024)
	waitLive(t, c, 2)

	ep.down()
	waitLive(t, c, 0)
	time.Sleep(1500 * time.Millisecond)
	up := time.Now()
	ep.up(t)

	deadline := time.Now().Add(3 * time.Second)
	for c.Stats().Live != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("через 3 с после блипа сессий %d из 2 (health: %s)", c.Stats().Live, c.h)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("сессии восстановлены через %v после возврата сервера", time.Since(up))
	echoRoundtrip(t, c, ep.addr, 1024)
}

// Один ендпоинт: 4 TLS к одной паре (IP,SNI) — аномалия, conns по умолчанию 2.
func TestConnsPerEndpoint(t *testing.T) {
	ep := newTestEP(t)
	if _, err := New(Config{
		Servers: []Endpoint{{Addr: ep.addr, SNI: "localhost"}},
		PSK:     testPSK, Conns: 4,
	}); err == nil {
		t.Fatal("New(conns=4) на одном ендпоинте прошёл")
	}
	c := newTestClient(t, 0, 0, ep.addr)
	if c.cfg.Conns != 2 {
		t.Fatalf("conns по умолчанию %d, ждали 2", c.cfg.Conns)
	}
	echoRoundtrip(t, c, ep.addr, 1024)
	waitLive(t, c, 2)
	time.Sleep(200 * time.Millisecond)
	if n := ep.count(); n != 2 {
		t.Fatalf("сервер принял %d соединений, ждали 2", n)
	}
}

// IP-ендпоинт без явного sni: Go не отправит SNI вовсе — отказ на старте.
func TestIPEndpointNeedsSNI(t *testing.T) {
	if _, err := New(Config{
		Servers: []Endpoint{{Addr: "192.0.2.1:443"}},
		PSK:     testPSK,
	}); err == nil || !strings.Contains(err.Error(), "sni") {
		t.Fatalf("IP без sni: %v, ждали ошибку про sni", err)
	}
	if _, err := New(Config{
		Servers: []Endpoint{{Addr: "192.0.2.1:443", SNI: "192.0.2.2"}},
		PSK:     testPSK,
	}); err == nil {
		t.Fatal("sni-литерал прошёл: SNI в hello не попадёт")
	}
	if _, err := New(Config{
		Servers: []Endpoint{{Addr: "192.0.2.1:443", SNI: "cover.example"}},
		PSK:     testPSK,
	}); err != nil {
		t.Fatalf("IP с явным sni: %v", err)
	}
}

// SetWriteDeadline(now) обязан разбудить уже блокирующийся Write: раньше его
// снимал только Reset.
func TestSetWriteDeadlineWakesWrite(t *testing.T) {
	ep := newStalledEP(t)
	c := newTestClient(t, 1, 0, ep.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(make([]byte, 32<<20)) // сервер не читает: окно кончится
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline(now): %v", err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = %v, ждали os.ErrDeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetWriteDeadline не разбудил Write")
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// NFR-11: в логах клиента только индекс ендпоинта — ни адреса, ни SNI.
func TestLogsNoEndpoint(t *testing.T) {
	const sni = "cover.example"
	var buf lockedBuf
	c, err := New(Config{
		Servers:  []Endpoint{{Addr: deadAddr(t), SNI: sni}},
		PSK:      testPSK,
		Insecure: true,
		Conns:    2,
		Logger:   slog.New(slog.NewTextHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c.DialContext(ctx, "tcp", "example.org:443") // стартует пул; сессии не будет

	out := buf.String()
	if out == "" {
		t.Fatal("лог пуст — тест ничего не проверил")
	}
	if strings.Contains(out, sni) {
		t.Fatalf("в логе SNI: %s", out)
	}
	if strings.Contains(out, "127.0.0.1") {
		t.Fatalf("в логе адрес ендпоинта: %s", out)
	}
}
