// Команда tmnc — SOCKS5-клиент TMN/1: одна TLS-сессия на все потоки (FR-1, §5 дизайна).
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tuman/mux"
	"tuman/proto"
	"tuman/shaper"
)

const (
	dialTimeout = 10 * time.Second
	backoffMin  = time.Second
	backoffMax  = 30 * time.Second
	alpn        = "h2"               // §1: мимикрия под браузер
	authLabel   = "TMN1-AUTH-RANDOM" // §4: exporter вместо client_random
	// Одно TCP-соединение упирается в своё окно (~290 Мбит/с на RTT 55 мс),
	// 4 соединения дают полосу маршрута (замерено iperf3: 227 -> 418 Мбит/с).
	defaultConns = 4
	maxConns     = 8
)

var errStopped = errors.New("tmnc: остановлен")

type config struct {
	Server      string // host:port сервера
	SNI         string
	PSKFile     string
	Insecure    bool   // только для тестов: без проверки серта
	SocksListen string // 127.0.0.1:1080
	SocksAuth   string // "user:pass"; пусто — метод 0x00
	Conns       int    // размер пула TCP-соединений (1..8)
	Profile     string // форма трафика: off|browse|video|bulk|voice
}

// parseTOML — плоский key = value; вложенных таблиц в конфиге клиента нет.
func parseTOML(data []byte) (map[string]string, error) {
	m := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("строка %d: нет '='", i+1)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			s, err := strconv.Unquote(v)
			if err != nil {
				// Windows-путь вида "C:\Users\x" — невалидный TOML-escape;
				// берём содержимое как есть, чтобы конфиг не падал на бэкслэшах.
				if strings.HasSuffix(v, `"`) && len(v) >= 2 {
					s = v[1 : len(v)-1]
				} else {
					return nil, fmt.Errorf("строка %d: %w", i+1, err)
				}
			}
			v = s
		} else if j := strings.IndexByte(v, '#'); j >= 0 { // shortcut: '#' в незакавыченном значении — только комментарий
			v = strings.TrimSpace(v[:j])
		}
		m[k] = v
	}
	return m, nil
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	insecure, err := strconv.ParseBool(m["insecure"])
	if err != nil && m["insecure"] != "" {
		return nil, fmt.Errorf("insecure: %w", err)
	}
	c := &config{
		Server:      m["server"],
		SNI:         m["sni"],
		PSKFile:     m["psk_file"],
		Insecure:    insecure,
		SocksListen: m["socks_listen"],
		SocksAuth:   m["socks_auth"],
		Profile:     m["profile"],
	}
	if c.Profile == "" {
		c.Profile = string(shaper.Off)
	}
	if !shaper.Profile(c.Profile).Valid() {
		return nil, fmt.Errorf("profile %q: off|browse|video|bulk|voice", c.Profile)
	}
	if c.Server == "" || c.PSKFile == "" {
		return nil, errors.New("нужны server и psk_file")
	}
	if c.SNI == "" {
		if host, _, err := net.SplitHostPort(c.Server); err == nil {
			c.SNI = host
		}
	}
	if c.SNI == "" {
		return nil, errors.New("нужен sni")
	}
	if c.SocksListen == "" {
		c.SocksListen = "127.0.0.1:1080"
	}
	c.Conns = defaultConns
	if v := m["conns"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxConns {
			return nil, fmt.Errorf("conns: нужно 1..%d", maxConns)
		}
		c.Conns = n
	}
	return c, nil
}

// loadPSK: 64 hex-символа или 32 сырых байта.
func loadPSK(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if s := strings.TrimSpace(string(b)); len(s) == 64 {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	if len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("psk: нужно 32 байта или 64 hex-символа")
}

// connector держит пул из Conns TLS-сессий: одно TCP-соединение упирается
// в своё окно (~290 Мбит/с на RTT 55 мс), пул из 4 даёт полосу маршрута.
type connector struct {
	cfg  *config
	psk  []byte
	log  *slog.Logger
	ctx  context.Context
	stop context.CancelFunc

	mu   sync.Mutex
	live []*mux.Session
	rr   int
	wait chan struct{} // закрывается при любой смене набора сессий

	once  sync.Once
	dials atomic.Int64 // сколько сессий установлено всего
}

func newConnector(cfg *config, psk []byte, log *slog.Logger) *connector {
	ctx, stop := context.WithCancel(context.Background())
	c := &connector{cfg: cfg, psk: psk, log: log, ctx: ctx, stop: stop, wait: make(chan struct{})}
	for i := 0; i < cfg.Conns; i++ {
		go c.slot()
	}
	return c
}

func (c *connector) Close() {
	c.once.Do(func() {
		c.stop()
		c.mu.Lock()
		live := c.live
		c.live = nil
		c.mu.Unlock()
		for _, s := range live {
			s.Close()
		}
	})
}

// slot держит одну сессию пула: подключается, живёт, переподключается.
func (c *connector) slot() {
	backoff := backoffMin
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-c.ctx.Done():
			return
		}
		s, err := c.dial()
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.log.Warn("соединение не установлено", "reason", reason(err), "retry_s", backoff.Seconds())
			t.Reset(backoff)
			if backoff *= 2; backoff > backoffMax {
				backoff = backoffMax
			}
			continue
		}
		backoff = backoffMin
		c.add(s)
		c.log.Info("сессия установлена", "total", c.dials.Add(1), "pool", c.size())
		select {
		case <-s.Done():
			c.log.Info("сессия потеряна", "pool", c.size()-1)
		case <-c.ctx.Done():
			s.Close()
			c.remove(s)
			return
		}
		c.remove(s)
		t.Reset(0)
	}
}

func (c *connector) add(s *mux.Session) {
	c.mu.Lock()
	c.live = append(c.live, s)
	close(c.wait)
	c.wait = make(chan struct{})
	c.mu.Unlock()
}

func (c *connector) remove(s *mux.Session) {
	c.mu.Lock()
	for i, x := range c.live {
		if x == s {
			c.live = append(c.live[:i], c.live[i+1:]...)
			break
		}
	}
	close(c.wait)
	c.wait = make(chan struct{})
	c.mu.Unlock()
}

func (c *connector) size() int {
	c.mu.Lock()
	n := len(c.live)
	c.mu.Unlock()
	return n
}

// pick — round-robin по живым сессиям: потоки раскидываются по разным TCP.
func (c *connector) pick() (*mux.Session, chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.live) == 0 {
		return nil, c.wait, false
	}
	c.rr++
	return c.live[c.rr%len(c.live)], c.wait, true
}

// open открывает поток в любой живой сессии; при обрыве пробует другую.
func (c *connector) open(ctx context.Context, target []byte) (*mux.Stream, error) {
	tries := 0
	for {
		if c.ctx.Err() != nil {
			return nil, errStopped
		}
		s, ch, ok := c.pick()
		if !ok {
			// ждём появления хоть одной сессии
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.ctx.Done():
				return nil, errStopped
			}
		}
		st, err := s.OpenStream(ctx, target)
		if err == nil {
			return st, nil
		}
		select {
		case <-s.Done(): // сессия умерла — пробуем следующую
			tries++
			if tries > 2*c.cfg.Conns {
				return nil, err
			}
			continue
		default:
			return nil, err
		}
	}
}

func (c *connector) dial() (*mux.Session, error) {
	ctx, cancel := context.WithTimeout(c.ctx, dialTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, err
	}
	// TCP_NODELAY: без него Nagle + отложенный ACK дают ступор на длинном RTT
	// (на VPS один поток падал до 32 Мбит/с при 195 у Reality).
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	t := tls.Client(raw, &tls.Config{
		ServerName:         c.cfg.SNI,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: c.cfg.Insecure,
	})
	if err := t.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	state := t.ConnectionState()
	exp, err := state.ExportKeyingMaterial(authLabel, nil, 32)
	if err != nil {
		t.Close()
		return nil, err
	}
	s, err := mux.New(shaper.New(t, shaper.Config{Profile: shaper.Profile(c.cfg.Profile)}),
		mux.Config{IsClient: true, PSK: c.psk, Exporter: exp})
	if err != nil {
		t.Close()
		return nil, err
	}
	return s, nil
}

// reason — короткая причина для лога: ни адресов, ни SNI, ни целей.
func reason(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, proto.ErrAuth):
		return "auth"
	case errors.Is(err, mux.ErrHandshake), errors.Is(err, mux.ErrProtocol), errors.Is(err, mux.ErrPingTimeout):
		return "protocol"
	}
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return "tls"
	}
	return "network"
}

type proxy struct {
	cfg *config
	con *connector
	log *slog.Logger
	ln  net.Listener
}

func start(cfg *config, psk []byte, log *slog.Logger) (*proxy, error) {
	// normalize: конфиг может прийти из теста без явного Conns
	if cfg.Conns < 1 {
		cfg.Conns = defaultConns
	}
	if cfg.Conns > maxConns {
		cfg.Conns = maxConns
	}
	if cfg.Insecure {
		log.Warn("проверка сертификата отключена (insecure)")
	}
	ln, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		return nil, err
	}
	p := &proxy{cfg: cfg, con: newConnector(cfg, psk, log), log: log, ln: ln}
	go p.serve()
	return p, nil
}

func (p *proxy) Addr() string { return p.ln.Addr().String() }

func (p *proxy) Close() {
	p.ln.Close()
	p.con.Close()
}

func main() {
	cfgPath := flag.String("config", "tmnc.toml", "путь к конфигу")
	lvl := flag.String("log-level", "", "debug|info|warn|error")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*lvl)}))
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Error("конфиг", "err", err)
		os.Exit(1)
	}
	psk, err := loadPSK(cfg.PSKFile)
	if err != nil {
		log.Error("psk", "err", err)
		os.Exit(1)
	}
	p, err := start(cfg, psk, log)
	if err != nil {
		log.Error("SOCKS5 не запущен", "err", err)
		os.Exit(1)
	}
	log.Info("SOCKS5 слушает", "addr", cfg.SocksListen)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	p.Close()
}

// parseLevel — тот же контракт, что у tmns; пустая строка = info.
func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
