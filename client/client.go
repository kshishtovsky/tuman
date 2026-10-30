// Package client — клиентская сторона TMN/1 (docs/03-system-design.md §5):
// пул TLS-сессий на весь процесс, один поток mux на каждое DialContext.
package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tuman/mux"
	"tuman/proto"
	"tuman/shaper"
)

const (
	dialTimeout = 10 * time.Second
	alpn        = "h2"               // §1: мимикрия под браузер
	authLabel   = "TMN1-AUTH-RANDOM" // §4: exporter вместо client_random
	// Одно TCP-соединение упирается в своё окно (~290 Мбит/с на RTT 55 мс),
	// 4 соединения дают полосу маршрута (замерено iperf3: 227 -> 418 Мбит/с).
	defaultConns = 4
	maxConns     = 8
)

var (
	// ErrClosed — клиент закрыт: новых потоков не будет.
	ErrClosed = errors.New("client: закрыт")
	// ErrNetwork — DialContext умеет только "tcp"; UDP в протоколе нет.
	ErrNetwork = errors.New("client: поддерживается только сеть tcp")
)

// Endpoint — один сервер и SNI под ним (у ендпоинтов SNI может отличаться).
type Endpoint struct {
	Addr string // host:port
	SNI  string // empty → Config.SNI, else Addr host
}

// Config — параметры клиента. Всё, что можно не задавать, имеет дефолт.
type Config struct {
	Servers  []Endpoint
	PSK      []byte
	SNI      string
	Insecure bool
	Conns    int           // 1..8, 0 → 4
	Profile  string        // off|browse|video|bulk|voice, empty → off
	Cooldown time.Duration // 0 → 30s
	Dialer   *net.Dialer   // nil → &net.Dialer{}; Android passes a protecting dialer here
	Logger   *slog.Logger  // nil → slog.Default()
}

// Stats — счётчики для логов и тестов.
type Stats struct {
	Dialed int // сколько сессий установлено всего
	Live   int // сколько живых в пуле прямо сейчас
}

// Client — пул TLS-сессий. Готов к параллельному использованию, потоки
// раскидываются по живым сессиям round-robin.
type Client struct {
	cfg  Config
	eps  []Endpoint
	log  *slog.Logger
	ctx  context.Context
	stop context.CancelFunc
	h    *health

	mu   sync.Mutex
	live []*mux.Session
	rr   int
	wait chan struct{} // закрывается при любой смене набора сессий

	// Пул стартует на первом DialContext, а не в New: мёртвый ендпоинт не
	// должен задерживать старт приложения (Android ждёт VPN до ready).
	started sync.Once
	once    sync.Once
	dials   atomic.Int64
}

// New проверяет конфиг и ничего не открывает: сети здесь нет.
func New(cfg Config) (*Client, error) {
	if len(cfg.Servers) == 0 {
		return nil, errors.New("client: нет ни одного ендпоинта")
	}
	eps := make([]Endpoint, len(cfg.Servers))
	for i, ep := range cfg.Servers {
		host, _, err := net.SplitHostPort(ep.Addr)
		if err != nil {
			return nil, fmt.Errorf("client: servers[%d]: %w", i, err)
		}
		sni := ep.SNI
		if sni == "" {
			sni = cfg.SNI
		}
		if sni == "" {
			sni = host
		}
		eps[i] = Endpoint{Addr: ep.Addr, SNI: sni}
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("client: psk — 32 байта")
	}
	switch {
	case cfg.Conns == 0:
		cfg.Conns = defaultConns
	case cfg.Conns < 0 || cfg.Conns > maxConns:
		return nil, fmt.Errorf("client: conns 1..%d", maxConns)
	}
	if cfg.Profile == "" {
		cfg.Profile = string(shaper.Off)
	}
	if !shaper.Profile(cfg.Profile).Valid() {
		return nil, fmt.Errorf("client: profile %q: off|browse|video|bulk|voice", cfg.Profile)
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Client{
		cfg: cfg, eps: eps, log: cfg.Logger, ctx: ctx, stop: stop,
		h:    newHealth(len(eps), cfg.Cooldown),
		wait: make(chan struct{}),
	}, nil
}

// DialContext открывает поток в одну из живых сессий; домен уходит на выход
// и резолвится там (proto.EncodeTarget). Ждёт появления сессии, но не дольше ctx.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrNetwork
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	target, err := proto.EncodeTarget(host, port)
	if err != nil {
		return nil, err
	}
	if c.ctx.Err() != nil {
		return nil, ErrClosed
	}
	c.start()
	st, err := c.open(ctx, target)
	if err != nil {
		return nil, err
	}
	return conn{st}, nil
}

// Close идемпотентен: повторный вызов ничего не делает.
func (c *Client) Close() error {
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
	return nil
}

// Stats — снимок счётчиков.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	live := len(c.live)
	c.mu.Unlock()
	return Stats{Dialed: int(c.dials.Load()), Live: live}
}

// conn превращает поток mux в net.Conn. Адресов и дедлайнов у потока нет:
// дедлайны игнорируются (shortcut: таймауты задаются ctx на DialContext, а не
// SetDeadline на потоке — понадобится, когда потребителю нужен таймаут Read/Write).
type conn struct{ *mux.Stream }

type streamAddr struct{}

func (streamAddr) Network() string { return "tmn" }
func (streamAddr) String() string  { return "" }

func (c conn) LocalAddr() net.Addr             { return streamAddr{} }
func (c conn) RemoteAddr() net.Addr            { return streamAddr{} }
func (c conn) SetDeadline(time.Time) error     { return nil }
func (c conn) SetReadDeadline(time.Time) error { return nil }
func (c conn) SetWriteDeadline(time.Time) error {
	return nil
}

// Reset отдаёт окно соединения пиру — нужен SOCKS-релею, чтобы брошенный
// поток не держал окно (io.Closer этого не умеет).
func (c conn) Reset() error { return c.Stream.Reset() }

var _ net.Conn = conn{}
var _ interface{ Reset() error } = conn{}
