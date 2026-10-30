package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tuman/mux"
)

var testPSK = bytes.Repeat([]byte{0x5A}, 32)

// testEP — тестовый TLS+mux сервер TMN: каждый поток эхом отдаёт полученное.
// Можно гасить и поднимать на том же адресе.
type testEP struct {
	addr string
	cfg  *tls.Config

	mu       sync.Mutex
	ln       net.Listener
	conns    []*tls.Conn
	sessions int
}

func newTestEP(t *testing.T) *testEP {
	t.Helper()
	e := &testEP{cfg: &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}}
	e.up(t)
	t.Cleanup(e.down)
	return e
}

func (e *testEP) up(t *testing.T) {
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
func (e *testEP) down() {
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

func (e *testEP) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions
}

func (e *testEP) serve(ln net.Listener) {
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

func (e *testEP) serveConn(c *tls.Conn) {
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
		go func() {
			defer st.Close()
			io.Copy(st, st) // эхо: клиенту возвращается всё, что он прислал
		}()
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tmn-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTestClient собирает клиента на n ендпоинтах; серт тестовый, поэтому insecure.
func newTestClient(t *testing.T, conns int, cool time.Duration, addrs ...string) *Client {
	t.Helper()
	eps := make([]Endpoint, len(addrs))
	for i, a := range addrs {
		eps[i] = Endpoint{Addr: a}
	}
	c, err := New(Config{
		Servers:  eps,
		PSK:      testPSK,
		SNI:      "localhost",
		Insecure: true,
		Conns:    conns,
		Cooldown: cool,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// waitLive опрашивает размер пула: 10 с на всё про всё, без фиксированных sleep.
func waitLive(t *testing.T, c *Client, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for c.Stats().Live != n {
		if time.Now().After(deadline) {
			t.Fatalf("в пуле %d сессий, ждали %d (health: %s)", c.Stats().Live, n, c.h)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// echoRoundtrip открывает поток, гоняет через него n байт и сверяет эхо.
func echoRoundtrip(t *testing.T, c *Client, addr string, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	p := payload(n, 7)
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(p)
		errc <- err
	}()
	got := make([]byte, len(p))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, p) {
		t.Fatal("эхо не совпало")
	}
}

func payload(n int, seed byte) []byte {
	b := make([]byte, n)
	x := uint32(seed) + 1
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// deadAddr — адрес, на котором заведомо никто не слушает (соединение отвергнут).
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// (a) Поток через DialContext ходит туда-обратно.
func TestDialContextEcho(t *testing.T) {
	ep := newTestEP(t)
	c := newTestClient(t, 1, 0, ep.addr)
	echoRoundtrip(t, c, ep.addr, 32<<10)
	if s := c.Stats(); s.Live != 1 || s.Dialed != 1 {
		t.Fatalf("stats: %+v", s)
	}
}

// (b) Всё, кроме "tcp", — отказ до сети: пул даже не стартует.
func TestDialContextNetwork(t *testing.T) {
	ep := newTestEP(t)
	c := newTestClient(t, 1, 0, ep.addr)
	for _, nw := range []string{"udp", "udp4", "tcp4", ""} {
		if _, err := c.DialContext(context.Background(), nw, ep.addr); !errors.Is(err, ErrNetwork) {
			t.Fatalf("сеть %q: %v, ждали ErrNetwork", nw, err)
		}
	}
	if s := c.Stats(); s.Live != 0 || s.Dialed != 0 {
		t.Fatalf("на отказе сети пул стартовал: %+v", s)
	}
}

// (c) Сессия потеряна — слот переподключается, следующий DialContext проходит.
func TestPoolReconnect(t *testing.T) {
	ep := newTestEP(t)
	c := newTestClient(t, 1, 0, ep.addr)
	echoRoundtrip(t, c, ep.addr, 4<<10)

	ep.down()
	waitLive(t, c, 0)
	ep.up(t)
	waitLive(t, c, 1)

	echoRoundtrip(t, c, ep.addr, 4<<10)
	if n := c.Stats().Dialed; n != 2 {
		t.Fatalf("установлено сессий: %d, ждали 2", n)
	}
}

// (d) После Close — ErrClosed; Close идемпотентен.
func TestClose(t *testing.T) {
	ep := newTestEP(t)
	c := newTestClient(t, 1, 0, ep.addr)
	echoRoundtrip(t, c, ep.addr, 1024)

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.DialContext(context.Background(), "tcp", ep.addr); !errors.Is(err, ErrClosed) {
		t.Fatalf("после Close: %v, ждали ErrClosed", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("второй Close: %v", err)
	}
}

// (e) Первый ендпоинт мёртв — слот уезжает на второй, потоки работают.
func TestDeadEndpointFailover(t *testing.T) {
	dead := deadAddr(t)
	ep := newTestEP(t)
	c := newTestClient(t, 2, 0, dead, ep.addr)

	echoRoundtrip(t, c, ep.addr, 8<<10)
	if n := ep.count(); n == 0 {
		t.Fatal("на живой ендпоинт не пришло ни одной сессии")
	}
	if ok, _ := c.h.usable(1); !ok {
		t.Fatal("живой ендпоинт в паузе")
	}
}

// Пул раскладывается по ендпоинтам: 4 соединения на 2 сервера = 2+2.
func TestPoolSpread(t *testing.T) {
	a, b := newTestEP(t), newTestEP(t)
	c := newTestClient(t, 4, 0, a.addr, b.addr)
	echoRoundtrip(t, c, a.addr, 1024) // пул стартует на первом DialContext

	waitLive(t, c, 4)
	deadline := time.Now().Add(10 * time.Second)
	for (a.count() != 2 || b.count() != 2) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if x, y := a.count(), b.count(); x != 2 || y != 2 {
		t.Fatalf("сессий по ендпоинтам %d/%d, ждали 2/2", x, y)
	}
	echoRoundtrip(t, c, a.addr, 4<<10)
	if s := c.h.String(); !strings.Contains(s, "ep=0") || !strings.Contains(s, "ep=1") {
		t.Fatalf("health: %s", s)
	}
}

// Падение первого ендпоинта: слот переезжает на второй, потоки продолжают работать.
func TestPoolFailover(t *testing.T) {
	a, b := newTestEP(t), newTestEP(t)
	c := newTestClient(t, 2, 0, a.addr, b.addr)
	echoRoundtrip(t, c, a.addr, 1024) // пул стартует на первом DialContext
	waitLive(t, c, 2)

	a.down()
	deadline := time.Now().Add(10 * time.Second)
	for b.count() != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	echoRoundtrip(t, c, b.addr, 4<<10)
	if n := a.count(); n != 1 {
		t.Fatalf("на упавший ендпоинт пришло %d сессий, ждали 1 (старую)", n)
	}
}

// Cooldown: после 2 ошибок подряд ендпоинт не трогают, потом отпускают,
// и слоты возвращаются на него без действий руками.
func TestPoolCooldownRelease(t *testing.T) {
	const cool = 2 * time.Second
	a, b := newTestEP(t), newTestEP(t)
	c := newTestClient(t, 4, cool, a.addr, b.addr)
	echoRoundtrip(t, c, a.addr, 1024) // пул стартует на первом DialContext
	waitLive(t, c, 4)
	deadline := time.Now().Add(10 * time.Second)
	for (a.count() != 2 || b.count() != 2) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	a.down()
	for b.count() != 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ok, rem := c.h.usable(0); ok || rem <= 0 {
		t.Fatalf("ep=0 не в паузе: ok=%v rem=%v", ok, rem)
	}
	for {
		ok, _ := c.h.usable(0)
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cooldown ep=0 не истёк")
		}
		time.Sleep(10 * time.Millisecond)
	}

	a.up(t)
	b.down()
	for a.count() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	waitLive(t, c, 4)
	echoRoundtrip(t, c, a.addr, 4<<10)
	if ok, _ := c.h.usable(0); !ok {
		t.Fatal("ep=0 снова в паузе после возврата")
	}
}

// (a) Дедлайн на выданном conn реально рвёт блокирующий Read (Rupas-релею это
// нужно, чтобы splice будил второй копировщик), а снятый дедлайн — снова нет.
func TestConnDeadline(t *testing.T) {
	ep := newTestEP(t)
	c := newTestClient(t, 1, time.Minute, ep.addr)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	errc := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 16)) // эхо-сервер молчит: Read висит
		errc <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if err := conn.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = %v, ждали os.ErrDeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetDeadline не разбудил Read")
	}

	// Без дедлайна conn снова рабочий — и на чтение, и на запись.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("снятие дедлайна: %v", err)
	}
	echo := func() {
		t.Helper()
		p := payload(64, 3)
		if _, err := conn.Write(p); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got := make([]byte, len(p))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if !bytes.Equal(got, p) {
			t.Fatal("эхо не совпало")
		}
	}
	echo()
	// Дедлайн записи в будущем проходит через WriteContext.
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	echo()
}
