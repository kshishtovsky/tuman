package main

// Пробы активного зондирования из docs/03-system-design.md §4 — против настоящего
// TLS-сервера на 127.0.0.1:0 (httptest здесь не годится: нужен свой серт и SNI).

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/proto"
)

// dialTo — TLS-клиент с заданным SNI и версией; пустой sni = без SNI.
func dialTo(addr, sni string, min, max uint16) (*tls.Conn, error) {
	return tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		MinVersion:         min,
		MaxVersion:         max,
		NextProtos:         []string{"http/1.1"},
	})
}

func mustDial(t *testing.T, addr, sni string) *tls.Conn {
	t.Helper()
	c, err := dialTo(addr, sni, tls.VersionTLS13, tls.VersionTLS13)
	if err != nil {
		t.Fatalf("handshake (sni=%q): %v", sni, err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(20 * time.Second))
	return c
}

// getPath — GET и разбор ответа; br можно передать свой, чтобы читать keep-alive.
func getPath(t *testing.T, c *tls.Conn, br *bufio.Reader, path string) (*http.Response, string) {
	t.Helper()
	if br == nil {
		br = bufio.NewReader(c)
	}
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: tmn.test\r\n\r\n"); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: тело: %v", path, err)
	}
	return resp, string(b)
}

func certNames(c *tls.Conn) []string {
	cs := c.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0].DNSNames
}

// 1. Свой SNI + GET /.
func TestProbeOwnSNI(t *testing.T) {
	addr, _ := start(t)
	c := mustDial(t, addr, "tmn.test")
	resp, body := getPath(t, c, nil, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d", resp.StatusCode)
	}
	if !strings.Contains(body, idxMarker) {
		t.Fatalf("не сайт-прикрытие: %q", body)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("протокол %q", resp.Proto)
	}
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("Server: %q", got)
	}
	if got := c.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN %q", got)
	}
	if names := certNames(c); len(names) == 0 || names[0] != "tmn.test" {
		t.Fatalf("серт %v", names)
	}
}

// 2. Свой SNI + неизвестный путь.
func TestProbeOwnSNI404(t *testing.T) {
	addr, _ := start(t)
	resp, body := getPath(t, mustDial(t, addr, "tmn.test"), nil, "/404")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("код %d", resp.StatusCode)
	}
	if !strings.Contains(body, nfMarker) {
		t.Fatalf("тело 404: %q", body)
	}
}

// 3. Чужой SNI (SNI-fronting): сервер отдаёт свой серт и работает как обычный сайт.
func TestProbeForeignSNI(t *testing.T) {
	addr, _ := start(t)
	c := mustDial(t, addr, "other.example")
	if names := certNames(c); len(names) == 0 || names[0] != "tmn.test" {
		t.Fatalf("серт %v", names)
	}
	if resp, _ := getPath(t, c, nil, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d", resp.StatusCode)
	}
}

// 4. Без SNI: TLS 1.3 не требует расширения — сервер отдаёт дефолтный серт.
func TestProbeNoSNI(t *testing.T) {
	addr, _ := start(t)
	c := mustDial(t, addr, "")
	if names := certNames(c); len(names) == 0 || names[0] != "tmn.test" {
		t.Fatalf("серт %v", names)
	}
	if resp, _ := getPath(t, c, nil, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d", resp.StatusCode)
	}
}

// 5. TLS 1.2: отказ на handshake, сервер после этого жив.
func TestProbeTLS12(t *testing.T) {
	addr, _ := start(t)
	c, err := dialTo(addr, "tmn.test", tls.VersionTLS10, tls.VersionTLS12)
	if err == nil {
		c.Close()
		t.Fatal("TLS 1.2 принят")
	}
	if resp, _ := getPath(t, mustDial(t, addr, "tmn.test"), nil, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("после отказа 1.2 сервер не отвечает: %d", resp.StatusCode)
	}
}

// 6. Невалидный AUTH: не мгновенно и не молчание — 400 как у keep-alive сервера.
func TestProbeInvalidAuthDelay(t *testing.T) {
	addr, _ := start(t)
	c := mustDial(t, addr, "tmn.test")
	pay := make([]byte, 50)
	rand.Read(pay)

	begin := time.Now()
	if err := proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, pay); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	el := time.Since(begin)
	if err != nil {
		t.Fatalf("ждали HTTP-ответ, получили %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("код %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("Content-Type %q", resp.Header.Get("Content-Type"))
	}
	if el < authIdle/2 {
		t.Fatalf("ответ мгновенный (%v) — выдаёт не-сайт", el)
	}
	if el > authIdle+3*time.Second {
		t.Fatalf("ответ через %v — дольше idle-таймаута", el)
	}
}

// 7. Невалидный (и повторённый) AUTH + GET: как keep-alive сервер — сайт.
func TestProbeInvalidAuthThenGET(t *testing.T) {
	addr, _ := start(t)
	for i := 0; i < 2; i++ { // второй проход — повтор того же кадра
		c := mustDial(t, addr, "tmn.test")
		pay := bytes.Repeat([]byte{0x5a}, 50)
		pay[1] = 1
		if err := proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, pay); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		resp, body := getPath(t, c, nil, "/")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, idxMarker) {
			t.Fatalf("итерация %d: код %d, тело %q", i, resp.StatusCode, body)
		}
	}
}

// 8. Replay валидного AUTH с чужим exporter: ключ не используется, идёт сайт.
func TestProbeReplayedAuth(t *testing.T) {
	addr, _ := start(t)
	pay, err := proto.MakeAuth(testPSK, bytes.Repeat([]byte{7}, 32), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := mustDial(t, addr, "tmn.test")
	if err := proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, pay); err != nil {
		t.Fatal(err)
	}
	resp, body := getPath(t, c, nil, "/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, idxMarker) {
		t.Fatalf("replay получил %d %q", resp.StatusCode, body)
	}
}

// 9. Много соединений с одного IP: до лимита — сайт, после — 429-страница nginx.
func TestProbeManyConnections(t *testing.T) {
	addr, _ := start(t)
	for i := 0; i < 20; i++ {
		resp, _ := getPath(t, mustDial(t, addr, "tmn.test"), nil, "/")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("соединение %d: код %d", i, resp.StatusCode)
		}
	}

	allowed, denied := 20, 0
	for i := 20; i < 40; i++ {
		resp, body := getPath(t, mustDial(t, addr, "tmn.test"), nil, "/")
		switch resp.StatusCode {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			denied++
			if !strings.Contains(body, "Too Many Requests") || !strings.Contains(body, "nginx") {
				t.Fatalf("429 не как у nginx: %q", body)
			}
			if got := resp.Header.Get("Retry-After"); got != "60" {
				t.Fatalf("Retry-After %q", got)
			}
			if got := resp.Header.Get("Server"); got != "" {
				t.Fatalf("Server: %q", got)
			}
		default:
			t.Fatalf("код %d вместо 200/429 — обрыв или ошибка протокола", resp.StatusCode)
		}
	}
	if denied == 0 {
		t.Fatalf("лимит %d/мин не сработал (%d×200)", ratePerMin, allowed)
	}
	if allowed < ratePerMin-3 || allowed > ratePerMin+2 {
		t.Fatalf("пропущено %d соединений из 40 при лимите %d", allowed, ratePerMin)
	}
}

// 10. Idle 15 с без единого байта: закрытие по таймауту, чистое (close_notify), не RST.
func TestProbeIdleNoRST(t *testing.T) {
	addr, _ := start(t)
	c := mustDial(t, addr, "tmn.test")
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	begin := time.Now()
	n, err := c.Read(make([]byte, 1))
	el := time.Since(begin)
	if n != 0 || err == nil {
		t.Fatalf("ждали закрытие, получили %d байт, %v", n, err)
	}
	if errors.Is(err, io.EOF) == false {
		t.Fatalf("закрытие не чистое: %v", err)
	}
	if el < 5*time.Second {
		t.Fatalf("оборвали через %v — не как keep-alive", el)
	}
}

// 11. Огромное тело: сервер отвечает и/или обрывает приём, но остаётся жив.
func TestProbeHugePOST(t *testing.T) {
	addr, _ := start(t)
	c := mustDial(t, addr, "tmn.test")
	const size = 8 << 20
	if _, err := io.WriteString(c, "POST / HTTP/1.1\r\nHost: tmn.test\r\nContent-Length: 8388608\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	for sent := 0; sent < size; sent += len(chunk) {
		if _, err := c.Write(chunk); err != nil {
			break // сервер закрыл приём: ответ мог уже уйти
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("код %d", resp.StatusCode)
		}
	}
	// главное: сервис жив и по-прежнему отдаёт сайт
	if resp2, _ := getPath(t, mustDial(t, addr, "tmn.test"), nil, "/"); resp2.StatusCode != http.StatusOK {
		t.Fatalf("после POST сервер отвечает %d", resp2.StatusCode)
	}
}

// Токен-бакет: лимит, чужой IP, очистка карты.
func TestLimiter(t *testing.T) {
	l := newLimiter(ratePerMin)
	a := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111}
	for i := 0; i < ratePerMin; i++ {
		if !l.allow(a) {
			t.Fatalf("токен %d отняли раньше лимита", i)
		}
	}
	if l.allow(a) {
		t.Fatalf("%d-е соединение пропустили", ratePerMin+1)
	}
	if !l.allow(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1}) {
		t.Fatal("чужой IP попал под чужой лимит")
	}

	l.mu.Lock()
	l.m["9.9.9.9"] = &bucket{tok: 1, seen: time.Now().Add(-time.Hour)}
	l.last = time.Now().Add(-time.Hour)
	l.mu.Unlock()
	l.allow(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1})
	l.mu.Lock()
	_, stale := l.m["9.9.9.9"]
	l.mu.Unlock()
	if stale {
		t.Fatal("просроченная запись осталась в карте")
	}
}

// httpStart: мусор с заглавной буквы не должен уходить в http.Server.
func TestHTTPStart(t *testing.T) {
	for _, s := range []string{"GET ", "POST", "HEAD", "OPTI"} {
		if !httpStart([]byte(s)) {
			t.Errorf("%q не распознан как запрос", s)
		}
	}
	for _, s := range []string{"", "Z", "Z\x00\x00\x00", "\x08\x00\x00\x00", "get "} {
		if httpStart([]byte(s)) {
			t.Errorf("%q принят за HTTP-запрос", s)
		}
	}
}
