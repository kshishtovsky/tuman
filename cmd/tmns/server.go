package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
	"github.com/kshishtovsky/tuman/shaper"
)

const (
	exporterLabel = "TMN1-AUTH-RANDOM" // §4: client_random заменён на TLS exporter
	hsWait        = 10 * time.Second   // §7: idle без AUTH
	dialWait      = 10 * time.Second
	copyBufSize   = 32 << 10
	peekLen       = 8 // заголовок кадра §2
)

var bufPool = sync.Pool{New: func() any { return new([copyBufSize]byte) }}

type server struct {
	psk  []byte
	site coverSite
	log  *slog.Logger
	tc   *tls.Config
	http *http.Server
	dial net.Dialer
	ctx  context.Context
	stop context.CancelFunc

	mu    sync.Mutex
	conns map[*tls.Conn]struct{}
	wg    sync.WaitGroup
	lim   *limiter

	nTunnel, nCover atomic.Int64
	prof            shaper.Profile // форма трафика для mux
}

// newServer — серт передаёт вызывающий: из файла в main, самоподписанный в тестах.
func newServer(c conf, psk []byte, certs []tls.Certificate, lg *slog.Logger) (*server, error) {
	cv, err := loadCover(c.CoverDir)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	s := &server{
		psk:   psk,
		site:  cv,
		log:   lg,
		ctx:   ctx,
		stop:  stop,
		conns: make(map[*tls.Conn]struct{}),
		prof:  shaper.Profile(c.Profile),
		lim:   newLimiter(ratePerMin),
		tc: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// http/1.1 первым: Go выбирает по порядку сервера, а статику прикрытия
			// (и весь HTTP-фолбэк) мы отдаём по h1. h2 остаётся в списке для ALPN-мимикрии.
			NextProtos:   []string{"http/1.1", "h2"},
			Certificates: certs,
		},
	}
	s.dial.Timeout = dialWait
	s.http = &http.Server{
		Handler: cv.handler(),
		// Сайт-прикрытие — статика по HTTP/1.1: h2 для него не реализован.
		ReadHeaderTimeout: hsWait,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0), // ни URL, ни адресов в stderr
	}
	return s, nil
}

func (s *server) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		// TCP_NODELAY: иначе Nagle + отложенный ACK режут поток на длинном RTT
		if raw, ok := c.(*net.TCPConn); ok {
			raw.SetNoDelay(true)
		}
		tc := tls.Server(c, s.tc)
		s.mu.Lock()
		s.conns[tc] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(tc)
		}()
	}
}

// shutdown закрывает соединения и ждёт горутины не дольше d.
func (s *server) shutdown(d time.Duration) {
	s.stop()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.http.Close()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

func (s *server) handle(tc *tls.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, tc)
		s.mu.Unlock()
		tc.Close()
	}()
	tc.SetDeadline(time.Now().Add(hsWait))
	if err := tc.HandshakeContext(s.ctx); err != nil {
		return // нет TLS 1.3 — тишина, без алертов
	}
	exporter := tc.ConnectionState()
	exp, err := exporter.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return
	}
	c := &conn{tc: tc, r: bufio.NewReaderSize(tc, 1<<12), closed: make(chan struct{})}
	// Смотрим первые 8 байт, не расходуя их: кадр TMN или HTTP-запрос.
	hdr, err := c.r.Peek(peekLen)
	if err != nil {
		return // молчание — закрываем как idle keep-alive
	}
	tc.SetDeadline(time.Time{})

	if tmnFrame(hdr) {
		sess, err := mux.New(shaper.New(c, shaper.Config{Profile: s.prof}), mux.Config{PSK: s.psk, Exporter: exp})
		if err == nil {
			s.nTunnel.Add(1)
			defer sess.Close()
			s.pump(sess)
			return
		}
		// AUTH не сошёлся — это не ошибка протокола, а обычный визит (§4).
		s.log.Debug("auth", "err", errKind(err))
	}
	s.fallback(c)
}

// fallback — невалидный AUTH или обычный HTTP-запрос. Держимся как keep-alive
// сервер: ждём запрос до idle-таймаута, только потом отвечаем 400 (не мгновенно).
func (s *server) fallback(c *conn) {
	if s.limited(c) {
		return
	}
	c.tc.SetReadDeadline(time.Now().Add(authIdle))
	if h, err := c.r.Peek(4); err == nil && httpStart(h) {
		c.tc.SetDeadline(time.Time{})
		s.cover(c) // запрос уже в буфере; съеденный AUTH отбрасываем
		return
	}
	c.tc.SetWriteDeadline(time.Now().Add(writeWait))
	c.tc.Write(errPage(400, "Bad Request", ""))
}

// httpStart — по первому байту мусор не отличить от запроса, поэтому по методу.
func httpStart(b []byte) bool {
	switch string(b) {
	case "GET ", "POST", "HEAD", "PUT ", "PATC", "DELE", "OPTI", "CONN":
		return true
	}
	return false
}

// limited — rate-limit на новые соединения с IP: 429 страницей nginx, без обрыва.
func (s *server) limited(c *conn) bool {
	if s.lim.allow(c.RemoteAddr()) {
		return false
	}
	c.tc.SetWriteDeadline(time.Now().Add(writeWait))
	c.Write(errPage(429, "Too Many Requests", "Retry-After: 60\r\n"))
	return true
}

// tmnFrame: клиент всегда начинает с AUTH, HTTP-методы не пересекаются с 0x08.
func tmnFrame(b []byte) bool {
	if len(b) < peekLen || b[0] != proto.TypeAuth {
		return false
	}
	_, err := proto.ParseHeader(b)
	return err == nil
}

// cover отдаёт статику и возвращается, когда http.Server закрыл соединение.
func (s *server) cover(c *conn) {
	s.nCover.Add(1)
	go func() {
		if err := s.http.Serve(&oneConn{c: c, a: c.LocalAddr()}); err != nil && !errors.Is(err, net.ErrClosed) {
			s.log.Debug("cover", "err", errKind(err))
		}
	}()
	<-c.closed
}

// pump — цикл egress: каждый входящий поток соединяем с целью из его адресного блока.
func (s *server) pump(sess *mux.Session) {
	for {
		st, err := sess.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.echo(st)
		}()
	}
}

func (s *server) echo(st *mux.Stream) {
	host, port, err := proto.DecodeTarget(st.Target())
	if err != nil {
		st.Close()
		s.log.Debug("egress", "err", "bad_target")
		return
	}
	addr := net.JoinHostPort(host, port)
	start := time.Now()
	up, err := s.dial.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		st.Close()
		s.log.Debug("egress", "err", errKind(err), "detail", err.Error())
		return
	}
	defer up.Close()
	var upN, downN atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // клиент → цель; по EOF полузакрываем цель
		defer wg.Done()
		b := bufPool.Get().(*[copyBufSize]byte)
		defer bufPool.Put(b)
		upN.Add(copyN(up, st, b[:]))
		closeWrite(up)
	}()
	go func() { // цель → клиент
		defer wg.Done()
		b := bufPool.Get().(*[copyBufSize]byte)
		defer bufPool.Put(b)
		downN.Add(copyN(st, up, b[:]))
		st.Close()
	}()
	wg.Wait()
	st.Reset() // освобождает поток у клиента и возвращает окно соединения
	s.log.Debug("stream", "up", upN.Load(), "down", downN.Load(), "ms", time.Since(start).Milliseconds(), "peer", up.RemoteAddr().String())
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
		return
	}
	c.Close()
}

// copyN — io.CopyBuffer с n, без ошибки: направление закрывается молча.
func copyN(dst io.Writer, src io.Reader, buf []byte) int64 {
	n, _ := io.CopyBuffer(dst, src, buf)
	return n
}

// conn — TLS-соединение с буфером: Peek нужен, чтобы не съесть AUTH/запрос.
type conn struct {
	tc     *tls.Conn
	r      *bufio.Reader
	once   sync.Once
	closed chan struct{}
}

func (c *conn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *conn) Write(p []byte) (int, error) { return c.tc.Write(p) }

func (c *conn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.tc.Close()
}

func (c *conn) LocalAddr() net.Addr                { return c.tc.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr               { return c.tc.RemoteAddr() }
func (c *conn) SetDeadline(t time.Time) error      { return c.tc.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.tc.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.tc.SetWriteDeadline(t) }

// oneConn — листенер на одно соединение; закрывает conn сам http.Server.
type oneConn struct {
	c net.Conn
	a net.Addr
}

func (l *oneConn) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, net.ErrClosed
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneConn) Close() error {
	l.c = nil
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.a }

// coverSite — статика, прочитанная на старте: без диска в hot path и без обхода путей.
type coverSite struct {
	index, notFound []byte
}

func loadCover(dir string) (coverSite, error) {
	var c coverSite
	var err error
	if c.index, err = os.ReadFile(filepath.Join(dir, "index.html")); err != nil {
		return c, err
	}
	if c.notFound, err = os.ReadFile(filepath.Join(dir, "404.html")); err != nil {
		return c, err
	}
	return c, nil
}

// handler: 200 на «/» и /index.html, 404 HTML на прочее (§1).
func (c coverSite) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Статика так не умеет: у nginx POST/PUT на файл — 405 Not Allowed.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			body := errBody(405, "Not Allowed")
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write(body)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		body, code := c.notFound, http.StatusNotFound
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			body, code = c.index, http.StatusOK
		}
		h.Set("Content-Length", strconv.Itoa(len(body))) // как у статик-сервера, без chunked
		w.WriteHeader(code)
		w.Write(body) // HEAD отбросит тело сам
	})
}

// errKind — код ошибки вместо текста: в логах не должно быть адресов (NFR-11).
func errKind(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, io.EOF), errors.Is(err, mux.ErrClosed), errors.Is(err, context.Canceled):
		return "closed"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, mux.ErrHandshake):
		return "handshake"
	case errors.Is(err, proto.ErrAuth):
		return "auth"
	}
	return "io"
}
