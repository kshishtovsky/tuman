package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// doh — резолвер целей поверх DNS-over-HTTPS (RFC 8484). Нужен потому, что
// системный резолвер спрашивает провайдера VPS открытым UDP/53: оттуда видно
// каждое имя, которое открывает клиент, и весь смысл туннеля теряется.
type doh struct {
	url string
	hc  *http.Client

	mu sync.Mutex
	c  map[string]dohEntry
}

type dohEntry struct {
	ips []netip.Addr
	exp time.Time
}

// ttlMin/ttlMax — границы кеша: 0 в ответе не должен превращаться в «спросить
// на каждый сокет», а суточный TTL не должен переживать смену A-записи.
const (
	ttlMin = 60 * time.Second
	ttlMax = time.Hour
)

func newDOH(raw string) (*doh, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("dns: нужен https://host/dns-query")
	}
	return &doh{url: raw, c: map[string]dohEntry{}, hc: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:      4,
			IdleConnTimeout:   90 * time.Second,
			ForceAttemptHTTP2: true,
		},
	}}, nil
}

// lookup отдаёт адреса цели. IP-литерал возвращается как есть, без запроса.
func (d *doh) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	d.mu.Lock()
	e, ok := d.c[host]
	d.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return e.ips, nil
	}

	type res struct {
		ips []netip.Addr
		ttl time.Duration
		err error
	}
	ch := make(chan res, 2)
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		go func(t dnsmessage.Type) {
			ips, ttl, err := d.query(ctx, host, t)
			ch <- res{ips, ttl, err}
		}(t)
	}
	var (
		ips []netip.Addr
		ttl = ttlMax
		err error
	)
	for range 2 {
		r := <-ch
		if r.err != nil {
			err = r.err
			continue
		}
		ips = append(ips, r.ips...)
		if r.ttl < ttl {
			ttl = r.ttl
		}
	}
	if len(ips) == 0 {
		if err == nil {
			err = errors.New("dns: нет A/AAAA")
		}
		return nil, err
	}
	// Один тип может упасть (например, AAAA), а другой ответить — это норма.
	// IPv4 первым: у большинства VPS нет IPv6, а «первый адрес» иначе окажется
	// недостижимым — AAAA часто приходит раньше A.
	slices.SortStableFunc(ips, func(a, b netip.Addr) int {
		switch {
		case a.Is4() && !b.Is4():
			return -1
		case !a.Is4() && b.Is4():
			return 1
		}
		return 0
	})
	if ttl < ttlMin {
		ttl = ttlMin
	}
	if ttl > ttlMax {
		ttl = ttlMax
	}
	d.mu.Lock()
	d.c[host] = dohEntry{ips: ips, exp: time.Now().Add(ttl)}
	d.mu.Unlock()
	return ips, nil
}

// query — один вопрос к DoH-серверу; TTL берётся минимальный из ответов.
func (d *doh) query(ctx context.Context, host string, t dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, 0, err
	}
	// GET с ?dns= запрещает кеширование на прокси в URL, поэтому POST.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(msg))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("dns: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	return parseAnswer(body, t)
}

// parseAnswer идёт по ответу до конца: CNAME-цепочка ставит адреса ПОСЛЕ
// псевдо-записи, поэтому останавливаться на первом не-A нельзя.
func parseAnswer(body []byte, t dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	var p dnsmessage.Parser
	h, err := p.Start(body)
	if err != nil {
		return nil, 0, err
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, 0, fmt.Errorf("dns: rcode %v", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, err
	}
	var (
		ips []netip.Addr
		ttl = ttlMax
	)
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, 0, err
			}
			ips = append(ips, netip.AddrFrom4(r.A))
			ttl = minTTL(ttl, ah.TTL)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, 0, err
			}
			ips = append(ips, netip.AddrFrom16(r.AAAA))
			ttl = minTTL(ttl, ah.TTL)
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, err
			}
		}
	}
	return ips, ttl, nil
}

func minTTL(cur time.Duration, secs uint32) time.Duration {
	if d := time.Duration(secs) * time.Second; d < cur {
		return d
	}
	return cur
}

// dialTarget превращает цель потока в адрес для net.Dialer. Без резолвера
// имя уходит в системный — как было до FR-9.
func (s *server) dialTarget(ctx context.Context, host, port string) (string, error) {
	if s.dns == nil {
		return net.JoinHostPort(host, port), nil
	}
	ips, err := s.dns.lookup(ctx, host)
	if err != nil {
		return "", err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", err
	}
	// Первый адрес: перебор остальных удваивал бы время отказа, а dns.lookup
	// уже отбросил недоступное семейство (A/AAAA падают независимо).
	return netip.AddrPortFrom(ips[0], uint16(p)).String(), nil
}
