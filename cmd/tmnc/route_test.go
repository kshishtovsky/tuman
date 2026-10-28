package main

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withRoutes перезапускает клиент с файлом правил на том же тестовом окружении.
func withRoutes(t *testing.T, e *env, src string) {
	t.Helper()
	e.p.Close()
	path := filepath.Join(t.TempDir(), "routes.toml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := start(&config{
		Server:      e.tlsAddr,
		SNI:         "localhost",
		Insecure:    true,
		SocksListen: "127.0.0.1:0",
		Conns:       1,
		RoutesFile:  path,
	}, testPSK, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	e.p = p
	e.socksAddr = p.Addr()
}

func waitPool(t *testing.T, e *env, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.p.con.size() < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.p.con.size() < n {
		t.Fatalf("в пуле %d сессий, ждали %d", e.p.con.size(), n)
	}
}

// Direct: эхо работает, TLS-сессия не открывается — даже если mux-сервер мёртв.
func TestSocksDirect(t *testing.T) {
	e := newEnv(t, "")
	withRoutes(t, e, "[[rule]]\naction = \"direct\"\ncidrs = [\"127.0.0.0/8\"]\n")
	waitPool(t, e, 1)

	sessions := e.sessionCount()
	dials := e.p.con.dials.Load()
	tunnelSrvDown(t, e)

	c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("direct connect: rep=%#x err=%v", rep, err)
	}
	if err := echoOnce(c, payload(64<<10, 11)); err != nil {
		t.Fatalf("direct echo: %v", err)
	}
	c.Close()

	if got := e.sessionCount(); got != sessions {
		t.Fatalf("TLS-сессий стало %d, было %d: прямой путь не должен ходить в туннель", got, sessions)
	}
	if got := e.p.con.dials.Load(); got != dials {
		t.Fatalf("клиент открыл %d сессий (было %d)", got, dials)
	}
}

// tunnelSrvDown закрывает тестовый mux-сервер: прямой маршрут от него не зависит.
func tunnelSrvDown(t *testing.T, e *env) {
	t.Helper()
	e.mu.Lock()
	e.ln.Close()
	for _, c := range e.conns {
		c.Close()
	}
	e.conns = nil
	e.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for e.p.con.size() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

// Block: rep 0x02, поток не открывается.
func TestSocksBlock(t *testing.T) {
	e := newEnv(t, "")
	withRoutes(t, e, "[[rule]]\naction = \"block\"\ndomains = [\"blocked.test\"]\n")

	if _, rep, err := socksConnect(e.socksAddr, "", "", "blocked.test:443", cmdConnect); err != nil || rep != repNotAllowed {
		t.Fatalf("blocked: rep=%#x err=%v, ждали %#x", rep, err, repNotAllowed)
	}
	// соседний домен по-прежнему идёт в туннель
	_, port, _ := net.SplitHostPort(e.echoAddr)
	c, rep, err := socksConnect(e.socksAddr, "", "", net.JoinHostPort("localhost", port), cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("tunnel: rep=%#x err=%v", rep, err)
	}
	if err := echoOnce(c, payload(4096, 4)); err != nil {
		t.Fatalf("tunnel echo: %v", err)
	}
	c.Close()
}

// Пустой routes_file — поведение как раньше: всё в туннель.
func TestSocksDefaultTunnel(t *testing.T) {
	e := newEnv(t, "")
	c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("connect: rep=%#x err=%v", rep, err)
	}
	if err := echoOnce(c, payload(8192, 6)); err != nil {
		t.Fatalf("echo: %v", err)
	}
	c.Close()
	if n := e.sessionCount(); n != 1 {
		t.Fatalf("TLS-сессий: %d, ждали 1", n)
	}
}

// Битый файл правил — клиент не стартует (лучше явная ошибка, чем тихо всё в туннель).
func TestSocksBadRoutesFile(t *testing.T) {
	e := newEnv(t, "")
	e.p.Close()
	path := filepath.Join(t.TempDir(), "routes.toml")
	if err := os.WriteFile(path, []byte("[[rule]]\ncidrs = [\"10.0.0.0/33\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := start(&config{
		Server:      e.tlsAddr,
		SNI:         "localhost",
		Insecure:    true,
		SocksListen: "127.0.0.1:0",
		RoutesFile:  path,
	}, testPSK, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("start с битым cidr не вернул ошибку")
	}
}
