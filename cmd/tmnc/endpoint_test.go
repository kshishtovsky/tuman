package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tuman/mux"
)

// testEp — тестовый TLS-сервер TMN, который можно гасить и поднимать на том же адресе.
type testEp struct {
	addr string
	cfg  *tls.Config

	mu       sync.Mutex
	ln       net.Listener
	conns    []*tls.Conn
	sessions int
}

func newTestEp(t *testing.T, cert tls.Certificate) *testEp {
	t.Helper()
	e := &testEp{cfg: &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}}
	e.up(t)
	t.Cleanup(e.down)
	return e
}

func (e *testEp) up(t *testing.T) {
	t.Helper()
	ln, err := tls.Listen("tcp", e.addr, e.cfg) // addr пуст у первого up
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	e.addr = ln.Addr().String()
	e.mu.Lock()
	e.ln = ln
	e.mu.Unlock()
	go e.serve(ln)
}

// down убивает сессии и закрывает листенер; адрес остаётся для повторного up.
func (e *testEp) down() {
	e.mu.Lock()
	ln := e.ln
	e.ln = nil
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
}

func (e *testEp) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions
}

func (e *testEp) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tc := c.(*tls.Conn)
		e.mu.Lock()
		e.conns = append(e.conns, tc)
		e.mu.Unlock()
		go e.serveConn(tc)
	}
}

func (e *testEp) serveConn(c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return
	}
	state := c.ConnectionState()
	exp, err := state.ExportKeyingMaterial(authLabel, nil, 32)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.sessions++
	e.mu.Unlock()
	s, err := mux.New(c, mux.Config{PSK: testPSK, Exporter: exp})
	if err != nil {
		return
	}
	defer s.Close()
	for {
		st, err := s.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go serveStream(st)
	}
}

type multiEnv struct {
	eps  []*testEp
	p    *proxy
	addr string
	echo string
}

// newMultiEnv поднимает n тестовых ендпоинтов и tmnc с пулом conns.
func newMultiEnv(t *testing.T, n, conns int, cool time.Duration) *multiEnv {
	t.Helper()
	m := &multiEnv{echo: startEcho(t, "127.0.0.1:0")}
	cert := selfSigned(t)
	cfg := &config{
		SNI:         "localhost",
		Insecure:    true,
		SocksListen: "127.0.0.1:0",
		Conns:       conns,
		CoolDown:    cool,
	}
	for i := 0; i < n; i++ {
		ep := newTestEp(t, cert)
		m.eps = append(m.eps, ep)
		cfg.Servers = append(cfg.Servers, endpoint{addr: ep.addr, sni: "localhost"})
	}
	p, err := start(cfg, testPSK, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(p.Close)
	m.p = p
	m.addr = p.Addr()
	return m
}

// wait опрашивает условие: 10 с на всё про всё, без фиксированных sleep.
func (m *multiEnv) wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: не дождались (pool=%d, ep=%s)", what, m.p.con.size(), m.p.con.h)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (m *multiEnv) checkStream(t *testing.T) {
	t.Helper()
	c, rep, err := socksConnect(m.addr, "", "", m.echo, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("CONNECT: rep=%#x err=%v", rep, err)
	}
	defer c.Close()
	if err := echoOnce(c, payload(32<<10, 4)); err != nil {
		t.Fatalf("эхо: %v", err)
	}
}

// Пул раскладывается по ендпоинтам: 4 соединения на 2 сервера = 2+2.
func TestMultiPoolSpread(t *testing.T) {
	m := newMultiEnv(t, 2, 4, 0)
	m.wait(t, "пул 4", func() bool { return m.p.con.size() == 4 })
	if a, b := m.eps[0].count(), m.eps[1].count(); a != 2 || b != 2 {
		t.Fatalf("сессий по ендпоинтам %d/%d, ждали 2/2", a, b)
	}
	m.checkStream(t)
	if s := m.p.con.h.String(); !strings.Contains(s, "ep=0") || !strings.Contains(s, "ep=1") {
		t.Fatalf("health: %s", s)
	}
}

// Падение первого ендпоинта: слот переезжает на второй, потоки продолжают работать.
func TestMultiFailover(t *testing.T) {
	m := newMultiEnv(t, 2, 2, 0)
	m.wait(t, "пул 2", func() bool { return m.p.con.size() == 2 })

	m.eps[0].down()
	m.wait(t, "обе сессии на ep=1", func() bool { return m.eps[1].count() == 2 })
	m.checkStream(t)
	if n := m.eps[0].count(); n != 1 {
		t.Fatalf("на упавший ендпоинт пришло %d сессий, ждали 1 (старую)", n)
	}
}

// Cooldown: после 2 ошибок подряд ендпоинт не трогают, потом отпускают,
// и слоты возвращаются на него без действий руками.
func TestMultiCooldownRelease(t *testing.T) {
	const cool = 2 * time.Second
	m := newMultiEnv(t, 2, 4, cool)
	m.wait(t, "пул 4", func() bool { return m.p.con.size() == 4 && m.eps[0].count() == 2 && m.eps[1].count() == 2 })

	m.eps[0].down()
	m.wait(t, "все сессии на ep=1", func() bool { return m.eps[1].count() == 4 })
	if ok, rem := m.p.con.h.usable(0); ok || rem <= 0 {
		t.Fatalf("ep=0 не в паузе: ok=%v rem=%v", ok, rem)
	}
	m.wait(t, "cooldown ep=0 истёк", func() bool { ok, _ := m.p.con.h.usable(0); return ok })

	m.eps[0].up(t)
	m.eps[1].down()
	m.wait(t, "сессии вернулись на ep=0", func() bool { return m.eps[0].count() >= 4 })
	m.wait(t, "пул снова 4", func() bool { return m.p.con.size() == 4 })
	m.checkStream(t)
	if ok, _ := m.p.con.h.usable(0); !ok {
		t.Fatal("ep=0 снова в паузе после возврата")
	}
}

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
	h.fail(0)
	if ok, _ := h.usable(0); !ok {
		t.Fatal("одна ошибка не должна давать паузу")
	}
	h.fail(0)
	ok, rem := h.usable(0)
	if ok || rem != 30*time.Second {
		t.Fatalf("пауза после 2 ошибок: ok=%v rem=%v", ok, rem)
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
		h.fail(0)
	}
	if _, rem := h.usable(0); rem != 300*time.Second {
		t.Fatalf("потолок паузы %v, ждали 5m", rem)
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

func TestLoadConfigServers(t *testing.T) {
	dir := t.TempDir()
	psk := filepath.Join(dir, "psk")
	if err := os.WriteFile(psk, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body+"psk_file = \""+filepath.ToSlash(psk)+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	c, err := loadConfig(write("multi.toml", `
sni = "www.example.com"
servers = ["a.example:443", "b.example:8443"]
servers_sni = ["a.example", "b.example"]
conns = 4
`))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(c.Servers) != 2 || c.Servers[0].addr != "a.example:443" || c.Servers[1].addr != "b.example:8443" {
		t.Fatalf("servers: %+v", c.Servers)
	}
	if c.Servers[0].sni != "a.example" || c.Servers[1].sni != "b.example" {
		t.Fatalf("servers_sni: %+v", c.Servers)
	}
	if c.Conns != 4 {
		t.Fatalf("conns: %d", c.Conns)
	}

	// legacy: только server — один ендпоинт, SNI из хоста
	c, err = loadConfig(write("one.toml", "server = \"x.example:443\"\n"))
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if len(c.Servers) != 1 || c.Servers[0].addr != "x.example:443" || c.Servers[0].sni != "x.example" || c.SNI != "x.example" {
		t.Fatalf("legacy servers: %+v sni=%q", c.Servers, c.SNI)
	}

	// общий sni без servers_sni — он же на всех
	c, err = loadConfig(write("shared.toml", "sni = \"cover.example\"\nservers = [\"a.example:443\", \"b.example:443\"]\n"))
	if err != nil {
		t.Fatalf("shared sni: %v", err)
	}
	if c.Servers[1].sni != "cover.example" {
		t.Fatalf("общий sni: %+v", c.Servers)
	}

	for _, bad := range []string{
		"servers = [\"a.example:443\", \"b.example:443\"]\nservers_sni = [\"a.example\"]\n",
		"servers = [\"a.example\"]\n", // нет порта
		"server = \"x.example:443\"\nservers = \"not-a-list\"\n",
	} {
		if _, err := loadConfig(write("bad.toml", bad)); err == nil {
			t.Fatalf("нет ошибки на конфиг %q", bad)
		}
	}
}
