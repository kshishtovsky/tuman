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
	"tuman/route"
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

// config — плоский tmnc.toml. Ендпоинты: servers = ["host1:port", "host2:port"]
// плюс общий sni и опционально servers_sni = ["a", "b"] (столько же значений,
// что servers; пустая строка — взять общий sni). Старое поле server = "host:port"
// работает как список из одного ендпоинта.
type config struct {
	Server      string     // legacy: один ендпоинт (обратная совместимость)
	Servers     []endpoint // servers[] в конфиге или один из Server
	SNI         string
	PSKFile     string
	Insecure    bool          // только для тестов: без проверки серта
	SocksListen string        // 127.0.0.1:1080
	SocksAuth   string        // "user:pass"; пусто — метод 0x00
	Conns       int           // размер пула TCP-соединений суммарно (1..8)
	CoolDown    time.Duration // пауза ендпоинта; 0 — 30 с (тесты задают короче)
	Profile     string        // форма трафика: off|browse|video|bulk|voice
	RoutesFile  string        // путь к routes.toml; пусто — всё в туннель
}

// endpoint — один сервер и SNI под ним (у ендпоинтов SNI может отличаться).
type endpoint struct {
	addr string
	sni  string
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

// splitList — однострочный TOML-массив: ["a:443", "b:443"].
// shortcut: запятая внутри элемента не поддержана — адреса и SNI её не содержат.
func splitList(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return nil, errors.New(`нужен массив ["a", "b"]`)
	}
	var out []string
	for _, p := range strings.Split(v[1:len(v)-1], ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, `"`) {
			s, err := strconv.Unquote(p)
			if err != nil {
				if len(p) < 2 || !strings.HasSuffix(p, `"`) {
					return nil, err
				}
				s = p[1 : len(p)-1]
			}
			p = s
		}
		out = append(out, p)
	}
	return out, nil
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
		SNI:         m["sni"],
		PSKFile:     m["psk_file"],
		Insecure:    insecure,
		SocksListen: m["socks_listen"],
		SocksAuth:   m["socks_auth"],
		Profile:     m["profile"],
		RoutesFile:  m["routes_file"],
	}
	if c.Profile == "" {
		c.Profile = string(shaper.Off)
	}
	if !shaper.Profile(c.Profile).Valid() {
		return nil, fmt.Errorf("profile %q: off|browse|video|bulk|voice", c.Profile)
	}
	// servers[] — основной список; server — обратная совместимость (один ендпоинт).
	addrs := []string{m["server"]}
	if v := m["servers"]; v != "" {
		if addrs, err = splitList(v); err != nil {
			return nil, fmt.Errorf("servers: %w", err)
		}
	}
	var snis []string
	if v := m["servers_sni"]; v != "" {
		if snis, err = splitList(v); err != nil {
			return nil, fmt.Errorf("servers_sni: %w", err)
		}
		if len(snis) != len(addrs) {
			return nil, fmt.Errorf("servers_sni: %d значений на %d серверов", len(snis), len(addrs))
		}
	}
	if len(addrs) == 0 || addrs[0] == "" {
		return nil, errors.New("нужны servers (список) и psk_file")
	}
	if c.PSKFile == "" {
		return nil, errors.New("нужен psk_file")
	}
	for i, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return nil, fmt.Errorf("servers[%d]: %w", i, err)
		}
		sni := c.SNI
		if len(snis) > 0 && snis[i] != "" {
			sni = snis[i]
		}
		if sni == "" {
			sni = host
		}
		c.Servers = append(c.Servers, endpoint{addr: a, sni: sni})
	}
	c.Server = addrs[0]
	if c.SNI == "" {
		c.SNI = c.Servers[0].sni
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
// Слоты распределены по ендпоинтам, health уводит их с упавших.
type connector struct {
	cfg  *config
	psk  []byte
	log  *slog.Logger
	ctx  context.Context
	stop context.CancelFunc
	eps  []endpoint
	h    *health

	mu   sync.Mutex
	live []*mux.Session
	rr   int
	wait chan struct{} // закрывается при любой смене набора сессий

	once  sync.Once
	dials atomic.Int64 // сколько сессий установлено всего
}

func newConnector(cfg *config, psk []byte, log *slog.Logger) *connector {
	ctx, stop := context.WithCancel(context.Background())
	c := &connector{
		cfg: cfg, psk: psk, log: log, ctx: ctx, stop: stop, wait: make(chan struct{}),
		eps: cfg.Servers,
		h:   newHealth(len(cfg.Servers), cfg.CoolDown),
	}
	for i := 0; i < cfg.Conns; i++ {
		go c.slot(i)
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
// idx задаёт домашний ендпоинт (пул раскладывается 2+2 по двум серверам).
func (c *connector) slot(idx int) {
	home := idx % len(c.eps)
	cur := home
	backoff := backoffMin
	fails := 0 // ошибок подряд в этом слоте: первый промах не ждём
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-c.ctx.Done():
			return
		}
		started := time.Now()
		s, err := c.dial(cur)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.h.fail(cur)
			prev := cur
			cur = c.h.next(cur)
			fails++
			wait := backoff
			ok, rem := c.h.usable(cur)
			switch {
			case !ok && rem > wait:
				wait = rem // ендпоинт в паузе — не долбим его раньше срока
			case ok && fails == 1:
				wait = 0 // первый промах — сразу пробуем соседа (G3: ≤60 с)
			}
			c.log.Warn("соединение не установлено", "ep", prev, "next", cur,
				"reason", reason(err), "retry_s", wait.Seconds())
			t.Reset(wait)
			if backoff *= 2; backoff > backoffMax {
				backoff = backoffMax
			}
			continue
		}
		c.h.ok(cur, time.Since(started))
		backoff, fails = backoffMin, 0
		c.add(s)
		c.log.Info("сессия установлена", "ep", cur, "total", c.dials.Add(1), "pool", c.size())
		select {
		case <-s.Done():
			c.log.Info("сессия потеряна", "ep", cur, "pool", c.size()-1)
		case <-c.ctx.Done():
			s.Close()
			c.remove(s)
			return
		}
		c.remove(s)
		// домашний ендпоинт ожил — возвращаемся на него, иначе идём по кругу
		// shortcut: ребаланс только при потере сессии, фоновой ротации пула нет
		if ok, _ := c.h.usable(home); ok {
			cur = home
		} else {
			cur = c.h.next(cur)
		}
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

func (c *connector) dial(i int) (*mux.Session, error) {
	ep := c.eps[i]
	ctx, cancel := context.WithTimeout(c.ctx, dialTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		return nil, err
	}
	// TCP_NODELAY: без него Nagle + отложенный ACK дают ступор на длинном RTT
	// (на VPS один поток падал до 32 Мбит/с при 195 у Reality).
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	t := tls.Client(raw, &tls.Config{
		ServerName:         ep.sni,
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
	// форма трафика — обёртка над TLS; при profile=off это прозрачный пропуск
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
	rt  *route.Table
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
	// legacy-конфиг: только server — список из одного ендпоинта
	if len(cfg.Servers) == 0 {
		if cfg.Server == "" {
			return nil, errors.New("нет ни одного ендпоинта")
		}
		cfg.Servers = []endpoint{{addr: cfg.Server, sni: cfg.SNI}}
	}
	if cfg.Insecure {
		log.Warn("проверка сертификата отключена (insecure)")
	}
	rt, err := route.LoadFile(cfg.RoutesFile)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		return nil, err
	}
	p := &proxy{cfg: cfg, con: newConnector(cfg, psk, log), rt: rt, log: log, ln: ln}
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
	log.Info("SOCKS5 слушает", "addr", cfg.SocksListen, "eps", len(cfg.Servers), "pool", cfg.Conns)

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
