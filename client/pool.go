package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
	"github.com/kshishtovsky/tuman/shaper"
)

const (
	// aliveMin: сессия, которая прожила меньше, — нерабочий ендпоинт. Иначе
	// сервер, принимающий TLS и сразу рвущий его, даёт флуд рукопожатий
	// (замерено: 6189 за 3 с), потому что после смерти шёл Reset(0).
	aliveMin = 5 * time.Second
	// probeMax: потолок паузы между пробами. Даже когда все ендпоинты в
	// кулдауне, канал обязан ожить за секунды (NFR-12: ≤3 с).
	probeMax = 2 * time.Second
)

// start поднимает слоты пула: ровно один раз, на первом DialContext.
func (c *Client) start() {
	c.started.Do(func() {
		for i := 0; i < c.cfg.Conns; i++ {
			go c.slot(i)
		}
	})
}

// slot держит одну сессию пула: подключается, живёт, переподключается.
// idx задаёт домашний ендпоинт: слоты делятся по ендпоинтам поровну, не больше
// perEndpoint на каждый (4 коннекта к одному (IP,SNI) — заметная аномалия).
func (c *Client) slot(idx int) {
	per := (c.cfg.Conns + len(c.eps) - 1) / len(c.eps)
	home := min(idx/per, len(c.eps)-1)
	cur := home
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
		var wait time.Duration
		if err == nil {
			c.h.ok(cur, time.Since(started))
			c.add(s)
			c.log.Info("сессия установлена", "ep", cur, "total", c.dials.Add(1), "pool", c.size())
			select {
			case <-s.Done():
			case <-c.ctx.Done():
				s.Close()
				c.remove(s)
				return
			}
			c.remove(s)
			age := time.Since(started)
			if age >= aliveMin {
				c.log.Info("сессия потеряна", "ep", cur, "pool", c.size())
				// домашний ендпоинт ожил — возвращаемся на него, иначе идём по кругу
				// shortcut: ребаланс только при потере сессии, фоновой ротации пула нет
				if ok, _ := c.h.usable(home); ok {
					cur = home
				} else {
					cur = c.h.next(cur)
				}
				t.Reset(0)
				continue
			}
			wait = c.failed(&cur, "сессия умерла сразу после установления", "ms", age.Milliseconds())
		} else {
			if c.ctx.Err() != nil {
				return
			}
			wait = c.failed(&cur, "соединение не установлено", "reason", reason(err))
		}
		t.Reset(wait)
	}
}

// failed отмечает промах на *cur, выбирает следующий ендпоинт и возвращает
// паузу до попытки: остаток кулдауна, но не дольше probeMax (иначе канал не
// оживёт за секунды), либо 0 — сосед доступен, идём к нему сразу.
// В логе только индекс: ни адреса, ни SNI (NFR-11).
func (c *Client) failed(cur *int, note string, attrs ...any) time.Duration {
	c.h.fail(*cur)
	prev := *cur
	*cur = c.h.next(prev)
	var wait time.Duration
	if ok, rem := c.h.usable(*cur); !ok {
		wait = min(rem, probeMax)
	}
	c.log.Warn(note, append(attrs, "ep", prev, "next", *cur, "retry_s", wait.Seconds())...)
	return wait
}

func (c *Client) add(s *mux.Session) {
	c.mu.Lock()
	c.live = append(c.live, s)
	close(c.wait)
	c.wait = make(chan struct{})
	c.mu.Unlock()
}

func (c *Client) remove(s *mux.Session) {
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

func (c *Client) size() int {
	c.mu.Lock()
	n := len(c.live)
	c.mu.Unlock()
	return n
}

// pick — round-robin по живым сессиям: потоки раскидываются по разным TCP.
// Сессию с уже закрытым done не выдаём: с момента её смерти до удаления из
// пула проходит мгновение, и поток, взятый в этот зазор, падает с «сессия
// закрыта» вместо того, чтобы сразу пойти в живую.
func (c *Client) pick() (*mux.Session, chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < len(c.live); i++ {
		c.rr++
		s := c.live[c.rr%len(c.live)]
		select {
		case <-s.Done():
			continue
		default:
		}
		return s, c.wait, true
	}
	return nil, c.wait, false
}

// Healthy — есть ли в пуле хоть одна живая сессия. Приложению это нужно,
// чтобы показать реальное состояние канала, а не «здоров» по последней пробе.
func (c *Client) Healthy() bool {
	_, _, ok := c.pick()
	return ok
}

// open открывает поток в любой живой сессии; при обрыве пробует другую.
func (c *Client) open(ctx context.Context, target []byte, udp bool) (*mux.Stream, error) {
	tries := 0
	for {
		if c.ctx.Err() != nil {
			return nil, ErrClosed
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
				return nil, ErrClosed
			}
		}
		st, err := s.OpenStreamKind(ctx, target, udp)
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
			// id потоков кончились: сессия жива, но новых потоков не даст —
			// закрываем её, слот переподключится.
			if errors.Is(err, mux.ErrExhausted) {
				s.Close()
				tries++
				if tries > 2*c.cfg.Conns {
					return nil, err
				}
				continue
			}
			return nil, err
		}
	}
}

func (c *Client) dial(i int) (*mux.Session, error) {
	ep := c.eps[i]
	ctx, cancel := context.WithTimeout(c.ctx, dialTimeout)
	defer cancel()
	// Dialer из конфига: у Android в Control висит VpnService.protect.
	raw, err := c.cfg.Dialer.DialContext(ctx, "tcp", ep.Addr)
	if err != nil {
		return nil, err
	}
	// TCP_NODELAY: без него Nagle + отложенный ACK дают ступор на длинном RTT
	// (на VPS один поток падал до 32 Мбит/с при 195 у Reality).
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	t, exp, err := c.handshake(ctx, raw, ep)
	if err != nil {
		raw.Close()
		return nil, err
	}
	// форма трафика — обёртка над TLS; при profile=off это прозрачный пропуск
	s, err := mux.New(shaper.New(t, shaper.Config{Profile: shaper.Profile(c.cfg.Profile)}),
		mux.Config{IsClient: true, PSK: c.cfg.PSK, Exporter: exp,
			PingEvery: c.cfg.PingEvery, PingMiss: c.cfg.PingMiss,
			AuthV2: c.cfg.AuthV2})
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
