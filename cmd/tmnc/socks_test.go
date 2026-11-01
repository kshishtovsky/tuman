package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/client"
	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

var testPSK = bytes.Repeat([]byte{0x5A}, 32)

type env struct {
	tlsAddr   string
	echoAddr  string
	socksAddr string
	p         *proxy

	tlsCfg *tls.Config
	ctx    context.Context

	mu        sync.Mutex
	ln        net.Listener
	conns     []*tls.Conn
	sessions  int             // сколько TLS-сессий принял тестовый сервер
	seenPorts map[string]bool // локальные порты клиента: пул = разные порты
}

func (e *env) sessionCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions
}

func (e *env) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tc := c.(*tls.Conn)
		e.mu.Lock()
		e.conns = append(e.conns, tc)
		if e.seenPorts == nil {
			e.seenPorts = map[string]bool{}
		}
		if _, port, err := net.SplitHostPort(tc.RemoteAddr().String()); err == nil {
			e.seenPorts[port] = true
		}
		e.mu.Unlock()
		go e.serveConn(e.ctx, tc)
	}
}

// restart убивает все сессии и поднимает сервер на том же адресе.
func (e *env) restart(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	for _, c := range e.conns {
		c.Close()
	}
	e.conns = nil
	old := e.ln
	e.mu.Unlock()
	old.Close()
	ln, err := tls.Listen("tcp", e.tlsAddr, e.tlsCfg)
	if err != nil {
		t.Fatalf("перезапуск сервера: %v", err)
	}
	e.mu.Lock()
	e.ln = ln
	e.mu.Unlock()
	go e.serve(ln)
}

// newEnv поднимает эхо-сервер, тестовый mux-сервер по TLS и сам tmnc.
func newEnv(t *testing.T, socksAuth string) *env {
	t.Helper()
	e := &env{}
	e.echoAddr = startEcho(t, "127.0.0.1:0")

	cert := selfSigned(t)
	e.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{client.ALPN},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", e.tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	e.ln = ln
	e.tlsAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	e.ctx = ctx
	t.Cleanup(func() {
		cancel()
		e.mu.Lock()
		e.ln.Close()
		for _, c := range e.conns {
			c.Close()
		}
		e.mu.Unlock()
		if e.p != nil {
			e.p.Close()
		}
	})
	go e.serve(ln)

	p, err := start(&config{
		Server:      e.tlsAddr,
		SNI:         "localhost",
		Insecure:    true,
		SocksListen: "127.0.0.1:0",
		SocksAuth:   socksAuth,
		Conns:       1, // тесты проверяют поведение одной сессии; пул — отдельным тестом
	}, testPSK, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	e.p = p
	e.socksAddr = p.Addr()
	return e
}

func (e *env) serveConn(ctx context.Context, c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return
	}
	state := c.ConnectionState()
	exp, err := state.ExportKeyingMaterial(client.AuthLabel, nil, 32)
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
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		st, err := s.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveStream(st)
	}
}

// serveStream — серверная сторона: коннект к цели из адресного блока §3.
func serveStream(st *mux.Stream) {
	defer st.Close()
	host, port, err := proto.DecodeTarget(st.Target())
	if err != nil {
		return
	}
	c, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(st, c)
		st.Close()
	}()
	io.Copy(c, st)
	closeWrite(c)
	<-done
}

func startEcho(t *testing.T, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("эхо-сервер на %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
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

// socksConnect — минимальный SOCKS5-клиент: rep > 0 значит отказ.
func socksConnect(addr, user, pass, target string, cmd byte) (net.Conn, byte, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	greet := []byte{socksVer, 1, mNoAuth}
	if user != "" {
		greet = []byte{socksVer, 2, mNoAuth, mUserPass}
	}
	if _, err := c.Write(greet); err != nil {
		c.Close()
		return nil, 0, err
	}
	var mr [2]byte
	if _, err := io.ReadFull(c, mr[:]); err != nil {
		c.Close()
		return nil, 0, err
	}
	switch mr[1] {
	case mNone:
		c.Close()
		return nil, 0, errors.New("socks: методы не приняты")
	case mUserPass:
		b := append([]byte{authVer, byte(len(user))}, user...)
		b = append(append(b, byte(len(pass))), pass...)
		if _, err := c.Write(b); err != nil {
			c.Close()
			return nil, 0, err
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			c.Close()
			return nil, 0, err
		}
		if ar[1] != 0 {
			c.Close()
			return nil, repFailure, nil // отказ в аутентификации
		}
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	req := []byte{socksVer, cmd, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req[3] = saIPv4
			req = append(req, v4...)
		} else {
			req[3] = saIPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req[3] = saDomain
		req = append(append(req, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, 0, err
	}
	var rh [4]byte
	if _, err := io.ReadFull(c, rh[:]); err != nil {
		c.Close()
		return nil, 0, err
	}
	var skip int
	switch rh[3] {
	case saIPv4:
		skip = 4 + 2
	case saIPv6:
		skip = 16 + 2
	case saDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, rh[1], err
		}
		skip = int(l[0]) + 2
	default:
		skip = 0
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
			c.Close()
			return nil, rh[1], err
		}
	}
	if rh[1] != repOK {
		c.Close()
		return nil, rh[1], nil
	}
	c.SetDeadline(time.Time{})
	return c, repOK, nil
}

// echoOnce отправляет payload и ждёт его обратно.
func echoOnce(c net.Conn, p []byte) error {
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(p)
		errc <- err
	}()
	got := make([]byte, len(p))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if err := <-errc; err != nil {
		return err
	}
	if !bytes.Equal(got, p) {
		return errors.New("эхо не совпало")
	}
	return nil
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

func TestSocksEcho100K(t *testing.T) {
	e := newEnv(t, "")
	c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("connect: rep=%#x err=%v", rep, err)
	}
	defer c.Close()
	if err := echoOnce(c, payload(100<<10, 7)); err != nil {
		t.Fatalf("100 КБ: %v", err)
	}
	if n := e.sessionCount(); n != 1 {
		t.Fatalf("TLS-сессий: %d, ждали 1", n)
	}
	if n := e.p.con.Stats().Dialed; n != 1 {
		t.Fatalf("клиент открыл сессий: %d", n)
	}
}

func TestSocksAddrs(t *testing.T) {
	e := newEnv(t, "")
	_, port, _ := net.SplitHostPort(e.echoAddr)
	v6 := startEcho(t, "[::1]:0")
	_, port6, _ := net.SplitHostPort(v6)

	cases := []struct{ name, target string }{
		{"ipv4", e.echoAddr},
		{"domain", net.JoinHostPort("localhost", port)},
		{"ipv6", net.JoinHostPort("::1", port6)},
	}
	for _, tc := range cases {
		c, rep, err := socksConnect(e.socksAddr, "", "", tc.target, cmdConnect)
		if err != nil || rep != repOK {
			t.Fatalf("%s: rep=%#x err=%v", tc.name, rep, err)
		}
		if err := echoOnce(c, payload(4096, 3)); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		c.Close()
	}
	if n := e.sessionCount(); n != 1 {
		t.Fatalf("TLS-сессий: %d, ждали 1", n)
	}
}

// Пять параллельных CONNECT в одной сессии; после их закрытия сессия жива.
func TestSocksParallel(t *testing.T) {
	e := newEnv(t, "")
	const n = 5
	conns := make([]net.Conn, n)
	for i := range conns {
		c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
		if err != nil || rep != repOK {
			t.Fatalf("connect %d: rep=%#x err=%v", i, rep, err)
		}
		conns[i] = c
	}
	errs := make(chan error, n)
	for i, c := range conns {
		go func(i int, c net.Conn) { errs <- echoOnce(c, payload(64<<10, byte(i))) }(i, c)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("поток %d: %v", i, err)
		}
	}
	for _, c := range conns {
		c.Close()
	}
	// поток закрыт — FIN, сессия продолжает жить и принимать новые потоки
	c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("после закрытия потоков: rep=%#x err=%v", rep, err)
	}
	if err := echoOnce(c, payload(1024, 9)); err != nil {
		t.Fatalf("после закрытия потоков: %v", err)
	}
	c.Close()

	if got := e.sessionCount(); got != 1 {
		t.Fatalf("TLS-сессий: %d, ждали 1", got)
	}
	if got := e.p.con.Stats().Dialed; got != 1 {
		t.Fatalf("клиент открыл сессий: %d, ждали 1", got)
	}
}

func TestSocksUDPAssociate(t *testing.T) {
	e := newEnv(t, "")
	_, rep, err := socksConnect(e.socksAddr, "", "", "0.0.0.0:0", 0x03)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if rep != repNoCommand {
		t.Fatalf("UDP ASSOCIATE: rep=%#x, ждали %#x", rep, repNoCommand)
	}
}

// Обрыв сессии: клиент переподключается, новые потоки идут в новое соединение.
func TestSocksReconnect(t *testing.T) {
	e := newEnv(t, "")
	c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("connect: rep=%#x err=%v", rep, err)
	}
	if err := echoOnce(c, payload(4096, 1)); err != nil {
		t.Fatalf("до обрыва: %v", err)
	}

	e.restart(t) // все сессии убиты, сервер поднят на том же адресе

	// старый поток обязан получить ошибку, а не тишину
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("старый поток не закрылся после обрыва сессии")
	}
	c.Close()

	c2, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("после обрыва: rep=%#x err=%v", rep, err)
	}
	defer c2.Close()
	if err := echoOnce(c2, payload(8192, 2)); err != nil {
		t.Fatalf("после обрыва: %v", err)
	}
	if got := e.p.con.Stats().Dialed; got != 2 {
		t.Fatalf("клиент открыл сессий: %d, ждали 2", got)
	}
	if got := e.sessionCount(); got != 2 {
		t.Fatalf("TLS-сессий: %d, ждали 2", got)
	}
}

func TestSocksAuth(t *testing.T) {
	e := newEnv(t, "user:secret")

	if _, rep, err := socksConnect(e.socksAddr, "user", "wrong", e.echoAddr, cmdConnect); err != nil || rep != repFailure {
		t.Fatalf("неверный пароль: rep=%#x err=%v", rep, err)
	}
	c, rep, err := socksConnect(e.socksAddr, "user", "secret", e.echoAddr, cmdConnect)
	if err != nil || rep != repOK {
		t.Fatalf("верный пароль: rep=%#x err=%v", rep, err)
	}
	if err := echoOnce(c, payload(2048, 5)); err != nil {
		t.Fatalf("верный пароль: %v", err)
	}
	c.Close()

	// клиент без метода 0x02 — сервер обязан отказать, не пускать по 0x00
	raw, err := net.Dial("tcp", e.socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := raw.Write([]byte{socksVer, 1, mNoAuth}); err != nil {
		t.Fatal(err)
	}
	var mr [2]byte
	if _, err := io.ReadFull(raw, mr[:]); err != nil {
		t.Fatalf("метод: %v", err)
	}
	if mr[1] != mNone {
		t.Fatalf("выбран метод %#x, ждали отказ", mr[1])
	}
}

// Регресс: SOCKS5 ATYP=3 — это DOMAIN, а не IPv6 (в нашем адресном блоке 3 = IPv6).
// До фикса домен читался как 16 байт адреса и CONNECT висел до дедлайна.
func TestSocksAtypIsIndependentOfProto(t *testing.T) {
	if saIPv4 != 1 || saDomain != 3 || saIPv6 != 4 {
		t.Fatalf("SOCKS5 ATYP: got %d/%d/%d, want 1/3/4", saIPv4, saDomain, saIPv6)
	}
	if proto.AtypDomain == saDomain {
		t.Fatal("константы совпали — легко перепутать снова")
	}
}

// Пул соединений: N сессий, потоки раскидываются по ним (round-robin),
// падение одной сессии не мешает открывать новые потоки.
func TestSocksPool(t *testing.T) {
	e := newEnv(t, "")
	// перезапуск с пулом из 3
	e.p.Close()
	e.mu.Lock()
	e.sessions = 0
	e.mu.Unlock()

	p, err := start(&config{
		Server:      e.tlsAddr,
		SNI:         "localhost",
		Insecure:    true,
		SocksListen: "127.0.0.1:0",
		Conns:       2, // больше двух на ендпоинт пул не открывает
	}, testPSK, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	e.p = p
	e.socksAddr = p.Addr()

	warm(t, e) // пул стартует на первом DialContext
	waitPool(t, e, 2)
	if n := e.p.con.Stats().Live; n != 2 {
		t.Fatalf("сессий в пуле: %d, ждали 2", n)
	}
	if n := e.sessionCount(); n != 2 {
		t.Fatalf("сервер принял %d TLS-соединений, ждали 2", n)
	}

	// 6 потоков подряд — все живые сессии должны поучаствовать
	for i := 0; i < 6; i++ {
		c, rep, err := socksConnect(e.socksAddr, "", "", e.echoAddr, cmdConnect)
		if err != nil || rep != repOK {
			t.Fatalf("поток %d: rep=%#x err=%v", i, rep, err)
		}
		if err := echoOnce(c, payload(2048, byte(i))); err != nil {
			t.Fatalf("поток %d: %v", i, err)
		}
		c.Close()
	}
	if n := e.sessionCount(); n != 2 {
		t.Fatalf("после 6 потоков сессий %d, ждали 2 (лишние не должны создаваться)", n)
	}
}

// Соединения пула должны иметь разные локальные порты — иначе это не разные TCP.
func TestSocksPoolDistinctTCP(t *testing.T) {
	e := newEnv(t, "")
	e.p.Close()
	e.mu.Lock()
	e.seenPorts = map[string]bool{}
	e.mu.Unlock()

	p, err := start(&config{
		Server:      e.tlsAddr,
		SNI:         "localhost",
		Insecure:    true,
		SocksListen: "127.0.0.1:0",
		Conns:       2,
	}, testPSK, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	e.p = p
	e.socksAddr = p.Addr()

	warm(t, e) // пул стартует на первом DialContext
	waitPool(t, e, 2)
	e.mu.Lock()
	n := len(e.seenPorts)
	e.mu.Unlock()
	if n != 2 {
		t.Fatalf("разных локальных портов: %d, ждали 2", n)
	}
}

// Предел одновременных CONNECT: при заполненном семафоре соединение рвётся сразу,
// а не копит поток в туннеле.
func TestSocksConnLimit(t *testing.T) {
	p := &proxy{log: slog.New(slog.DiscardHandler), sem: make(chan struct{}, 1)}
	p.sem <- struct{}{} // единственный слот занят
	a, b := net.Pipe()
	defer b.Close()
	p.handle(a)
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("соединение не закрыто при заполненном лимите")
	}
}
