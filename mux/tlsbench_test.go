package mux

// Bench на реальном транспорте: TLS 1.3 поверх TCP loopback (а не net.Pipe).
// Отвечает на вопрос этапа 2: сколько даёт mux+AEAD на настоящем стеке.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"tuman/proto"
)

func benchCert() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"bench.local"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// exporterFor берёт 32 байта из TLS так, как требует спека §4.
func exporterFor(cs tls.ConnectionState) []byte {
	b, err := cs.ExportKeyingMaterial("TMN1-AUTH-RANDOM", nil, 32)
	if err != nil {
		panic(err)
	}
	return b
}

// pairTLS поднимает TLS-пару и возвращает две mux-сессии.
func pairTLS(tb testing.TB) (*Session, *Session, func()) {
	tb.Helper()
	psk := make([]byte, 32)
	rand.Read(psk)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{benchCert()},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		tb.Fatal(err)
	}

	type srvRes struct {
		s   *Session
		err error
	}
	ch := make(chan srvRes, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- srvRes{nil, err}
			return
		}
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			ch <- srvRes{nil, err}
			return
		}
		s, err := New(tc, Config{PSK: psk, Exporter: exporterFor(tc.ConnectionState())})
		ch <- srvRes{s, err}
	}()

	dc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		tb.Fatal(err)
	}
	cli, err := New(dc, Config{IsClient: true, PSK: psk, Exporter: exporterFor(dc.ConnectionState())})
	if err != nil {
		tb.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		tb.Fatal(r.err)
	}
	return cli, r.s, func() { cli.Close(); r.s.Close(); ln.Close() }
}

// echoOnce принимает один поток и отражает байты.
func echoOnce(tb testing.TB, srv *Session) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := srv.AcceptStream(ctx)
	if err != nil {
		tb.Logf("accept: %v", err)
		return
	}
	go func() {
		io.Copy(st, st)
		st.Close()
	}()
}

func transfer(tb testing.TB, cli *Session, mb int) {
	tb.Helper()
	tgt, _ := proto.EncodeTarget("127.0.0.1", "9")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := cli.OpenStream(ctx, tgt)
	if err != nil {
		tb.Fatal(err)
	}
	defer st.Close()

	payload := make([]byte, 32<<10)
	n := int64(mb) << 20
	done := make(chan int64, 1)
	go func() {
		got, _ := io.CopyN(io.Discard, st, n)
		done <- got
	}()
	start := time.Now()
	var sent int64
	for sent < n {
		w, err := st.Write(payload)
		if err != nil {
			break
		}
		sent += int64(w)
	}
	got := <-done
	sec := time.Since(start).Seconds()
	mbs := float64(got) / sec / 1e6
	tb.Logf("mux+TLS loopback: %.0f MB/s payload = %.0f Mbit/s (1 поток, %d МБ, %.2fs)",
		mbs, mbs*8, mb, sec)
}

func TestMuxOverTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("долгий тест")
	}
	cli, srv, stop := pairTLS(t)
	defer stop()
	go echoOnce(t, srv)
	transfer(t, cli, 256)
}

func TestMuxOverTLSParallel(t *testing.T) {
	if testing.Short() {
		t.Skip("долгий тест")
	}
	cli, srv, stop := pairTLS(t)
	defer stop()
	for i := 0; i < 8; i++ {
		go echoOnce(t, srv)
	}
	errc := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			tgt, _ := proto.EncodeTarget("127.0.0.1", "9")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			st, err := cli.OpenStream(ctx, tgt)
			if err != nil {
				errc <- err
				return
			}
			defer st.Close()
			buf := make([]byte, 16<<10)
			n := 4 << 20
			go func() { io.CopyN(io.Discard, st, int64(n)) }()
			sent := 0
			for sent < n {
				w, err := st.Write(buf)
				if err != nil {
					errc <- err
					return
				}
				sent += w
			}
			errc <- nil
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("поток %d: %v", i, err)
		}
	}
}

func TestSessionNewWithBadPSK(t *testing.T) {
	psk1 := make([]byte, 32)
	psk2 := make([]byte, 32)
	rand.Read(psk1)
	rand.Read(psk2)
	exp := make([]byte, 32)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{benchCert()},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tc := c.(*tls.Conn)
		tc.Handshake()
		_, _ = New(tc, Config{PSK: psk1, Exporter: exp})
		tc.Close()
	}()

	dc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	s, err := New(dc, Config{IsClient: true, PSK: psk2, Exporter: exp})
	if err == nil {
		s.Close()
		t.Fatal("ожидался отказ handshake при неверном PSK")
	}
	fmt.Println("ok: неверный PSK отклонён:", err)
}
