package main

// Тесты на ужесточение: SSRF-фильтр egress, отсутствие адресов и SNI в логах,
// ALPN без h2. Сеть не нужна — кроме двух тестов, которые поднимают сервер на
// 127.0.0.1:0 (AllowPrivateEgress=true снимает фильтр для них).

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/proto"
)

func TestEgressAllowed(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:80", false},
		{"169.254.169.254:80", false},
		{"10.0.0.1:1", false},
		{"172.16.0.1:1", false},
		{"192.168.1.1:1", false},
		{"100.64.0.1:1", false},
		{"0.0.0.0:1", false},
		{"192.0.0.1:1", false},
		{"198.18.0.1:1", false},
		{"224.0.0.1:1", false},
		{"255.255.255.255:1", false},
		{"[::1]:443", false},
		{"[::]:443", false},
		{"[fe80::1]:443", false},
		{"[fe80::1%eth0]:443", false}, // зона не должна обходить фильтр
		{"[fc00::1]:443", false},
		{"[::ffff:127.0.0.1]:443", false}, // IPv4-mapped loopback
		{"[::ffff:10.0.0.1]:443", false},
		{"[ff02::1]:443", false},
		{"not-an-addr", false},
		{"1.1.1.1:443", true},
		{"[2606:4700::1111]:443", true},
	} {
		err := egressAllowed("tcp", tc.addr, false)
		if (err == nil) != tc.ok {
			t.Errorf("%s: allowed=%v, ждали %v (err=%v)", tc.addr, err == nil, tc.ok, err)
			continue
		}
		// адрес не должен попадать в текст ошибки: он идёт в лог (NFR-11)
		if err != nil && err.Error() != "egress denied" {
			t.Errorf("%s: текст ошибки %q", tc.addr, err)
		}
	}
	// флаг для тестов снимает фильтр (туннель на 127.0.0.1)
	if err := egressAllowed("tcp", "127.0.0.1:80", true); err != nil {
		t.Fatalf("AllowPrivateEgress не разрешил 127.0.0.1: %v", err)
	}
}

// newServer ставит Control у dialer: без флага 127.0.0.1 режется.
func TestEgressControlInstalled(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/index.html", "i")
	write(t, dir+"/404.html", "n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, allow := range []bool{false, true} {
		s, err := newServer(conf{CoverDir: dir, AllowPrivateEgress: allow}, testPSK, []tls.Certificate{testCert(t)},
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if s.dial.Control == nil {
			t.Fatal("dial.Control не выставлен")
		}
		err = s.dial.Control("tcp", "127.0.0.1:443", nil)
		if (err == nil) != allow {
			t.Fatalf("allowPrivate=%v: err=%v", allow, err)
		}
		if err != nil && strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("адрес в тексте ошибки: %v", err)
		}
		// настоящий dial через dialer: Control реально вызывается ОС-путём
		c, err := s.dial.DialContext(context.Background(), "tcp", ln.Addr().String())
		if allow {
			if err != nil {
				t.Fatalf("разрешённый dial не прошёл: %v", err)
			}
			c.Close()
			continue
		}
		if !errors.Is(err, errEgressDenied) || errKind(err) != "egress_denied" {
			t.Fatalf("запрещённый dial: %v (%s)", err, errKind(err))
		}
	}
}

// TestNoH2ALPN: h2 не должно быть ПЕРВЫМ — тогда браузерный зонд получит h1,
// как прикрытие. Наличие h2 вторым обязательно: клиенты, просящие только h2,
// иначе падают на ALPN (проверено старым бинарником против нового сервера).
// В TLS 1.3 выбор едет в EncryptedExtensions и пассивному DPI не виден.
func TestNoH2ALPN(t *testing.T) {
	addr, s := start(t)
	if len(s.tc.NextProtos) == 0 || s.tc.NextProtos[0] != "http/1.1" {
		t.Fatalf("http/1.1 должен быть первым: %v", s.tc.NextProtos)
	}
	if got := mustDial(t, addr, "tmn.test").ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("браузерный hello получил ALPN %q", got)
	}
	// h2-only клиент (парк до апгрейда) обязан пройти handshake.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{
		ServerName: "tmn.test", MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"}, InsecureSkipVerify: true,
	})
	if err := c.Handshake(); err != nil {
		t.Fatalf("h2-only клиент не прошёл handshake: %v", err)
	}
	if got := c.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("h2-only клиент получил %q", got)
	}
	c.Close()
}

// syncBuf — лог для горутин сервера.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// NFR-11: в debug-логе потока нет ни host:port цели, ни SNI клиента.
func TestNoTargetInLogs(t *testing.T) {
	var lg syncBuf
	addr, _ := startLog(t, slog.New(slog.NewTextHandler(&lg, &slog.HandlerOptions{Level: slog.LevelDebug})))
	echo := echoServer(t)
	s := client(t, addr, testPSK) // SNI secret.example
	ctx := context.Background()

	// успешный поток: цель = echo-сервер на 127.0.0.1
	host, port, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := proto.EncodeTarget(host, port)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.OpenStream(ctx, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// неуспешный поток: закрытый порт — путь лога egress с ошибкой dial
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	if h, p, err := net.SplitHostPort(dead); err == nil {
		if tgt, err := proto.EncodeTarget(h, p); err == nil {
			if st, err := s.OpenStream(ctx, tgt); err == nil {
				st.Read(make([]byte, 1))
				st.Close()
			}
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := lg.String()
		if strings.Contains(got, "msg=stream") && strings.Contains(got, "msg=egress") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := lg.String()
	if !strings.Contains(got, "msg=stream") {
		t.Fatalf("лога потока нет: %q", got)
	}
	for _, bad := range []string{"127.0.0.1", dead, "secret.example"} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q попало в лог: %q", bad, got)
		}
	}
	// полезное осталось
	for _, want := range []string{"up=", "down=", "ms=", "err="} {
		if !strings.Contains(got, want) {
			t.Fatalf("в логе нет %q: %q", want, got)
		}
	}
}
