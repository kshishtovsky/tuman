package client

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
)

// helloSrv — сервер, который запоминает ClientHello и принимает сессию по
// AUTH v2. Нужен именно v2: uTLS не отдаёт TLS-exporter, как и настоящий tmns.
type helloSrv struct {
	addr  string
	mu    sync.Mutex
	seen  []*tls.ClientHelloInfo
	conns []net.Conn
	errs  []error
}

func newHelloSrv(t *testing.T) *helloSrv {
	t.Helper()
	s := &helloSrv{}
	srv := &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		MinVersion:   tls.VersionTLS13,
		// как у tmns: h1 первым (прикрытие), h2 вторым
		NextProtos: []string{ALPN, "h2"},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			s.mu.Lock()
			s.seen = append(s.seen, hi)
			s.mu.Unlock()
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	s.addr = ln.Addr().String()
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			go s.serve(c.(*tls.Conn))
		}
	}()
	return s
}

func (s *helloSrv) serve(c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		s.mu.Lock()
		s.errs = append(s.errs, err)
		s.mu.Unlock()
		return
	}
	sess, err := mux.New(c, mux.Config{PSK: testPSK, AuthV2: true})
	if err != nil {
		s.mu.Lock()
		s.errs = append(s.errs, err)
		s.mu.Unlock()
		return
	}
	defer sess.Close()
	for {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer st.Close()
			io.Copy(st, st)
		}()
	}
}

func (s *helloSrv) hello(t *testing.T) *tls.ClientHelloInfo {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) == 0 {
		t.Fatal("сервер не увидел ни одного ClientHello")
	}
	return s.seen[len(s.seen)-1]
}

// fpClient — клиент с выбранным отпечатком: всегда AUTH v2, иначе New ругается.
func fpClient(t *testing.T, fp, addr string) *Client {
	t.Helper()
	c, err := New(Config{
		Servers:     []Endpoint{{Addr: addr, SNI: "tmn.test"}},
		PSK:         testPSK,
		Insecure:    true,
		Conns:       1,
		AuthV2:      true,
		Fingerprint: fp,
	})
	if err != nil {
		t.Fatalf("New(%q): %v", fp, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// echo через туннель: проверяет, что hello, AUTH v2 и mux работают вместе.
func echoOnce(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "target.test:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	want := []byte("hello через отпечаток браузера")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("эхо: %q != %q", got, want)
	}
}

// chromeSuites — порядок шифров из настоящего Chrome: AES-128, AES-256,
// ChaCha. Go по умолчанию ставит ChaCha первым на клиентах без AES-ускорения,
// а с AES-NI — 0x1301; поэтому порядок сравниваем не с Go, а с Chrome.
var chromeSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

// Три браузерных профиля: сессия поднимается, эхо возвращается, а hello на
// проводе действительно браузерный — это единственное, ради чего uTLS и нужен.
func TestFingerprintBrowsers(t *testing.T) {
	for _, fp := range []string{"chrome", "firefox", "safari"} {
		t.Run(fp, func(t *testing.T) {
			srv := newHelloSrv(t)
			c := fpClient(t, fp, srv.addr)
			echoOnce(t, c)

			hi := srv.hello(t)
			if len(hi.CipherSuites) < 3 {
				t.Fatalf("%s: шифров в hello %d — hello не браузерный", fp, len(hi.CipherSuites))
			}
			// Chrome подмешивает GREASE (0x?A?A) — это признак живого браузера,
			// поэтому сравниваем три первых шифра, отбросив grease-заглушки.
			if fp == "chrome" {
				first := nonGrease(hi.CipherSuites)
				if len(first) < 3 {
					t.Fatalf("chrome: шифров без grease %d", len(first))
				}
				for i := range chromeSuites {
					if first[i] != chromeSuites[i] {
						t.Fatalf("chrome: шифры %v, ждали %v", first[:3], chromeSuites)
					}
				}
			}
			if len(hi.SupportedCurves) < 2 {
				t.Fatalf("%s: кривых %d — hello вырожденный", fp, len(hi.SupportedCurves))
			}
			if len(hi.SupportedProtos) < 2 || hi.SupportedProtos[0] != "h2" {
				t.Fatalf("%s: ALPN %v — браузер предлагает h2 первым", fp, hi.SupportedProtos)
			}
			if hi.ServerName == "" {
				t.Fatalf("%s: hello без SNI — заметная аномалия", fp)
			}
		})
	}
}

// nonGrease отбрасывает GREASE-значения (0x0a0a, 0x1a1a, … 0xfafa).
func nonGrease(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if v&0x0f0f == 0x0a0a {
			continue
		}
		out = append(out, v)
	}
	return out
}

// Отпечаток отличается от Go: иначе весь uTLS был бы бесполезен. Сравниваем
// полный список шифров двух профилей на одном и том же сервере.
func TestFingerprintDiffersFromGo(t *testing.T) {
	srv := newHelloSrv(t)
	cc := fpClient(t, "chrome", srv.addr)
	if s, err := cc.dial(0); err != nil {
		t.Fatalf("chrome dial: %v", err)
	} else {
		s.Close()
	}

	srv2 := newHelloSrv(t)
	plain := fpClient(t, "", srv2.addr) // off → crypto/tls
	echoOnce(t, plain)

	got := srv2.hello(t)
	if len(got.CipherSuites) == 0 {
		t.Fatal("нет шифров в Go-hello")
	}
	srv.mu.Lock()
	chrome := srv.seen[0]
	srv.mu.Unlock()
	if len(chrome.CipherSuites) == len(got.CipherSuites) &&
		chrome.CipherSuites[0] == got.CipherSuites[0] &&
		chrome.CipherSuites[len(chrome.CipherSuites)-1] == got.CipherSuites[len(got.CipherSuites)-1] {
		t.Fatalf("chrome-hello не отличается от Go: %v", got.CipherSuites)
	}
}

// Без AuthV2 отпечаток не имеет привязки к каналу: это ошибка конфига, а не
// разрыв на первом dial в рантайме.
func TestFingerprintNeedsAuthV2(t *testing.T) {
	_, err := New(Config{
		Servers:     []Endpoint{{Addr: "127.0.0.1:1"}},
		PSK:         testPSK,
		Fingerprint: "chrome",
	})
	if err == nil {
		t.Fatal("New принял fingerprint без auth_v2")
	}
}

func TestFingerprintUnknown(t *testing.T) {
	_, err := New(Config{
		Servers:     []Endpoint{{Addr: "127.0.0.1:1"}},
		PSK:         testPSK,
		AuthV2:      true,
		Fingerprint: "opera",
	})
	if err == nil {
		t.Fatal("New принял неизвестный отпечаток")
	}
}
