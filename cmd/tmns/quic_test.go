package main

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// startQUIC поднимает сервер с QUIC-ендпоинтом рядом с TCP.
func startQUIC(t *testing.T) (string, *server) {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "index.html"), "<!doctype html><title>q</title>")
	write(t, filepath.Join(dir, "404.html"), "<!doctype html><title>nf</title>")
	s, err := newServer(conf{CoverDir: dir, AllowPrivateEgress: true}, testPSK, []tls.Certificate{testCert(t)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", s.quicTLS(), quicConf())
	if err != nil {
		t.Fatal(err)
	}
	go s.serveQUIC(ln)
	t.Cleanup(func() {
		ln.Close()
		s.shutdown(5 * time.Second)
	})
	return ln.Addr().String(), s
}

// quicDial — рукопожатие с заданным ALPN, мимо client/ (чтобы тест не зависел
// от пула).
func quicDial(t *testing.T, addr string, alpn []string) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		ServerName:         "secret.example",
		NextProtos:         alpn,
	}, quicConf())
	if err != nil {
		t.Fatalf("QUIC dial: %v", err)
	}
	t.Cleanup(func() { c.CloseWithError(0, "") })
	return c
}

// quicSession — поток и mux поверх готового соединения: ровно то, что делает
// dialQUIC после рукопожатия.
func quicSession(t *testing.T, c *quic.Conn) *mux.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := mux.New(&quicCarrier{Stream: st, conn: c},
		mux.Config{IsClient: true, PSK: testPSK, AuthV2: true})
	if err != nil {
		t.Fatalf("mux.New по QUIC: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// quicClient — новый клиент: ALPN как у браузера, h3 обязан согласоваться.
func quicClient(t *testing.T, addr string) *mux.Session {
	t.Helper()
	c := quicDial(t, addr, alpnQUIC)
	if p := c.ConnectionState().TLS.NegotiatedProtocol; p != alpnQUIC[0] {
		t.Fatalf("согласован ALPN %q, ожидался %q", p, alpnQUIC[0])
	}
	return quicSession(t, c)
}

// Сервер должен согласовать h3 с новым клиентом и tuman со старым (≤ v0.2.1):
// парк обновляется не разом, отказ старому ALPN выключил бы туннель у части
// пользователей. Проверяем не только имя, но и mux поверх согласованного ALPN.
func TestQUICALPNNegotiation(t *testing.T) {
	addr, _ := startQUIC(t)
	for _, tc := range []struct {
		name  string
		offer []string
		want  string
	}{
		{"новый клиент", []string{"h3"}, "h3"},
		{"старый клиент", []string{"tuman"}, "tuman"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := quicDial(t, addr, tc.offer)
			got := c.ConnectionState().TLS.NegotiatedProtocol
			if got != tc.want {
				t.Fatalf("согласован ALPN %q, ожидался %q", got, tc.want)
			}
			quicSession(t, c) // AUTH проходит — канал рабочий, не только handshake
		})
	}
}

// 1 МБ в обе стороны через QUIC-ендпоинт.
func TestQUICTunnelEcho(t *testing.T) {
	addr, _ := startQUIC(t)
	echo := echoServer(t)
	s := quicClient(t, addr)

	host, port, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := proto.EncodeTarget(host, port)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.OpenStream(context.Background(), tgt)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() { st.Write(payload); st.Close() }() // эхо-цель закроет поток по EOF
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("вернулось %d байт вместо %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("расхождение на байте %d", i)
		}
	}
}

// Чужой QUIC-клиент без нашего ключа: поток закрывается, сессия к tуnnel не
// причисляется. Проверяем, что сервер не падает и считает попытку отдельно.
func TestQUICWrongKey(t *testing.T) {
	addr, s := startQUIC(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := quicDial(t, addr, alpnQUIC)
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bad := make([]byte, 32)
	if _, err := mux.New(&quicCarrier{Stream: st, conn: c},
		mux.Config{IsClient: true, PSK: bad, AuthV2: true}); err == nil {
		t.Fatal("сервер принял неверный ключ")
	}
	time.Sleep(200 * time.Millisecond)
	if n := s.nTunnel.Load(); n != 0 {
		t.Fatalf("невалидный AUTH засчитан как туннель: %d", n)
	}
	if n := s.nQUIC.Load(); n != 1 {
		t.Fatalf("попыток QUIC %d, ожидалась 1", n)
	}
}
