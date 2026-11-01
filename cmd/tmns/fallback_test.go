package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/proto"
)

var testPSK = bytes.Repeat([]byte{0x42}, 32)

const (
	idxMarker = "cover-index-marker"
	nfMarker  = "cover-404-marker"
)

// start поднимает сервер на 127.0.0.1:0 с самоподписанным сертом и cover_dir.
func start(t *testing.T) (string, *server) {
	t.Helper()
	return startLog(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// startLog — то же, но с переданным логгером (см. тест NFR-11).
func startLog(t *testing.T, lg *slog.Logger) (string, *server) {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "index.html"), "<!doctype html><title>"+idxMarker+"</title>")
	write(t, filepath.Join(dir, "404.html"), "<!doctype html><title>"+nfMarker+"</title>")

	// AllowPrivateEgress — тестовый egress на 127.0.0.1, иначе SSRF-фильтр режет.
	s, err := newServer(conf{CoverDir: dir, AllowPrivateEgress: true}, testPSK, []tls.Certificate{testCert(t)}, lg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.serve(ln)
	t.Cleanup(func() {
		ln.Close()
		s.shutdown(5 * time.Second)
	})
	return ln.Addr().String(), s
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tmn.test"},
		DNSNames:     []string{"tmn.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func dial(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(15 * time.Second))
	return c
}

// Обычный браузерный обмен: 200 на «/» и 404 на прочее в том же keep-alive.
func TestCoverSiteHTTP(t *testing.T) {
	addr, _ := start(t)
	c := dial(t, addr)
	br := bufio.NewReader(c)

	for _, tc := range []struct {
		path string
		code int
		mark string
	}{
		{"/", http.StatusOK, idxMarker},
		{"/nope", http.StatusNotFound, nfMarker},
		{"/index.html", http.StatusOK, idxMarker},
	} {
		if _, err := io.WriteString(c, "GET "+tc.path+" HTTP/1.1\r\nHost: tmn.test\r\n\r\n"); err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if resp.StatusCode != tc.code {
			t.Fatalf("%s: код %d, ждали %d", tc.path, resp.StatusCode, tc.code)
		}
		if !strings.Contains(string(body), tc.mark) {
			t.Fatalf("%s: тело %q", tc.path, body)
		}
		if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Fatalf("%s: Content-Type %q", tc.path, got)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("%s: заголовков статики нет (%q)", tc.path, got)
		}
		if resp.ContentLength <= 0 {
			t.Fatalf("%s: нет Content-Length (как у статик-сервера)", tc.path)
		}
		if got := resp.Header.Get("Server"); got != "" {
			t.Fatalf("%s: выдали Server: %q", tc.path, got)
		}
	}
}

// Невалидный AUTH: на проводе обычный HTTP-ответ, а не TLS alert и не RST.
func TestInvalidPSKGetsSite(t *testing.T) {
	addr, _ := start(t)
	c := dial(t, addr)
	pay := make([]byte, 50)
	pay[1] = 1 // ver=1, тег — мусор
	if err := proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, pay); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("ждали HTTP-ответ, получили %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 ") {
		t.Fatalf("не HTTP-ответ: %q", buf[:n])
	}
}

// Повтор AUTH на другом соединении не проходит: тег привязан к exporter TLS-сессии,
// поэтому чужой/старый кадр получает сайт-прикрытие, а не AUTH_OK.
func TestStaleAuthGetsSite(t *testing.T) {
	addr, _ := start(t)
	pay, err := proto.MakeAuth(testPSK, bytes.Repeat([]byte{7}, 32), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := dial(t, addr)
	if err := proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, pay); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 128)
	n, err := c.Read(b)
	if err != nil || !strings.HasPrefix(string(b[:n]), "HTTP/1.1 ") {
		t.Fatalf("stale AUTH: %q, %v", b[:n], err)
	}
}

func exporterOf(t *testing.T, c *tls.Conn) []byte {
	t.Helper()
	cs := c.ConnectionState()
	exp, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return exp
}

// Живое соединение не держит остановку: shutdown завершается за секунды, не за таймаут.
func TestShutdownWithLiveConn(t *testing.T) {
	addr, s := start(t)
	c := dial(t, addr)
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: tmn.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	s.shutdown(3 * time.Second)
	if d := time.Since(begin); d > 2*time.Second {
		t.Fatalf("shutdown занял %v", d)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("соединение после shutdown не закрыто")
	}
}
