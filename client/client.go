// Package client — клиентская сторона TMN/1 (docs/03-system-design.md §5):
// пул TLS-сессий на весь процесс, один поток mux на каждое DialContext.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
	"github.com/kshishtovsky/tuman/shaper"
)

const (
	dialTimeout = 10 * time.Second
	// ALPN — что клиент предлагает. Порядок как у настоящего браузера (h2
	// первым), иначе один http/1.1 в ClientHello — примета не-браузера.
	// Выбор делает сервер (у него http/1.1 первым), а кадр mux бинарный в любом
	// случае, поэтому на протокол после TLS значение не влияет.
	ALPN = "http/1.1"

	// AuthLabel — exporter вместо client_random (§4).
	AuthLabel = "TMN1-AUTH-RANDOM"
	// Одно TCP-соединение упирается в своё окно (~290 Мбит/с на RTT 55 мс),
	// 4 соединения дают полосу маршрута (замерено iperf3: 227 -> 418 Мбит/с).
	DefaultConns = 4
	MaxConns     = 8
	// perEndpoint — больше двух TLS с одного адреса к одному (IP,SNI) — уже
	// аномалия для наблюдателя, lab-правило режет >3 за минуту.
	perEndpoint = 2
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
	// PingEvery/PingMiss — детект мёртвой сессии на уровне mux (0 → 25s/3).
	// Мобильный клиент ставит туже: после Doze иначе минуту не видно, что
	// поток уже мёртв, и приложение висит на «Подключение».
	PingEvery time.Duration
	PingMiss  int
	// AuthV2 — просить AUTH v2 (X25519 + MAC сервера). Сервер принимает обе
	// версии всегда, поэтому флаг безопасен: старый клиент продолжает работать.
	AuthV2 bool
	// Fingerprint — отпечаток ClientHello: off (пусто), chrome, firefox,
	// safari, golang. С uTLS exporter TLS недоступен, поэтому без AuthV2
	// привязка к каналу не работает — New такой конфиг отвергает.
	Fingerprint string
}

// ALPNList — предложение в том же порядке, что у браузера: h2 первым.
var ALPNList = []string{"h2", ALPN}

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
	sess    tls.ClientSessionCache
	hl      hello
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
			return nil, fmt.Errorf("client: servers[%d]: нужен host:port", i) // без адреса: NFR-11
		}
		sni := ep.SNI
		if sni == "" {
			sni = cfg.SNI
		}
		if sni == "" {
			sni = host
		}
		// IP-литерал Go в SNI не отправляет: hello уходит без SNI — очень
		// заметная аномалия, поэтому такой конфиг отвергаем на старте.
		if net.ParseIP(sni) != nil {
			return nil, fmt.Errorf("client: servers[%d]: ендпоинт задан IP — нужен явный sni", i)
		}
		eps[i] = Endpoint{Addr: ep.Addr, SNI: sni}
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("client: psk — 32 байта")
	}
	if limit := perEndpoint * len(eps); cfg.Conns == 0 {
		cfg.Conns = min(DefaultConns, limit)
	} else if cfg.Conns < 1 || cfg.Conns > min(MaxConns, limit) {
		return nil, fmt.Errorf("client: conns %d: 1..%d и не больше %d на ендпоинт (%d ендпоинтов)",
			cfg.Conns, min(MaxConns, limit), perEndpoint, len(eps))
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
	hl, err := newHello(cfg.Fingerprint, 2*cfg.Conns)
	if err != nil {
		return nil, err
	}
	// uTLS не отдаёт ExportKeyingMaterial: с ним единственная привязка к
	// каналу — AUTH v2. Проверяем здесь, чтобы это была ошибка конфига, а
	// не разрыв на первом dial.
	if hl.On && !cfg.AuthV2 {
		return nil, errors.New("client: fingerprint " + cfg.Fingerprint +
			": нужен auth_v2 (uTLS не отдаёт TLS-exporter)")
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Client{
		cfg: cfg, eps: eps, log: cfg.Logger, ctx: ctx, stop: stop,
		h:    newHealth(len(eps), cfg.Cooldown),
		wait: make(chan struct{}),
		// кеш тикетов: переподключение идёт resumption'ом, а не полным
		// рукопожатием (в hello появляется ext 41 — как у браузера).
		sess: tls.NewLRUClientSessionCache(2 * cfg.Conns),
		hl:   hl,
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
	return &conn{Stream: st}, nil
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

// conn превращает поток mux в net.Conn: дедлайн чтения живёт в mux.Stream,
// дедлайн записи превращается в context на время Write.
type conn struct {
	*mux.Stream
	mu    sync.Mutex
	wdl   time.Time          // под mu
	wstop context.CancelFunc // отмена активного Write с дедлайном; под mu
}

type streamAddr struct{}

func (streamAddr) Network() string { return "tmn" }
func (streamAddr) String() string  { return "" }

func (c *conn) LocalAddr() net.Addr  { return streamAddr{} }
func (c *conn) RemoteAddr() net.Addr { return streamAddr{} }

func (c *conn) SetReadDeadline(t time.Time) error { return c.Stream.SetReadDeadline(t) }

// SetWriteDeadline взводит дедлайн записи и будит уже блокирующийся Write:
// без отмены его context поток висит до таймаута mux, даже если писать больше некуда.
func (c *conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	stop := c.wstop
	c.mu.Unlock()
	if stop != nil && !t.IsZero() && !t.After(time.Now()) {
		stop()
	}
	return nil
}

func (c *conn) SetDeadline(t time.Time) error {
	c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

// Write уважает дедлайн записи: без него — обычный Stream.Write без аллокации
// контекста, с ним — WriteContext, ждущий окно не дольше дедлайна.
func (c *conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	dl := c.wdl
	c.mu.Unlock()
	if dl.IsZero() {
		return c.Stream.Write(p)
	}
	ctx, cancel := context.WithDeadline(context.Background(), dl)
	c.mu.Lock()
	c.wstop = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.wstop = nil
		c.mu.Unlock()
		cancel()
	}()
	n, err := c.Stream.WriteContext(ctx, p)
	// Canceled — это SetWriteDeadline(now) из другого потока: для вызывающего
	// это тот же дедлайн, что и истёкший.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

var _ net.Conn = (*conn)(nil)

// Reset (метод mux.Stream) нужен SOCKS-релею: брошенный поток не должен держать
// окно соединения (io.Closer этого не умеет).
var _ interface{ Reset() error } = (*conn)(nil)
