package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// errEgressDenied — отказ SSRF-фильтра. Текста без адреса: он идёт в лог (NFR-11).
var errEgressDenied = errors.New("egress denied")

// noEgress — куда egress не ходит: своя сеть, метаданные облака, CGNAT, служебные
// диапазоны. Цель приходит из клиентского кадра, поэтому блок-лист, а не allow-list.
var noEgress = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"), // multicast
	netip.MustParsePrefix("240.0.0.0/4"), // reserved, включая 255.255.255.255
	netip.MustParsePrefix("::/128"),      // unspecified
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), // multicast
}

// egressAllowed — Control у net.Dialer: проверка уже разрезолвленного IP, поэтому
// localhost и DNS rebinding (evil.tld -> 127.0.0.1) ловятся на самом коннекте.
// Первый аргумент — сигнатура Control; в ошибку адрес не попадает.
func egressAllowed(_, addr string, allowPrivate bool) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return errEgressDenied // неразобранный адрес — тоже отказ
	}
	if allowPrivate { // тестовый флаг: egress на 127.0.0.1
		return nil
	}
	ip := ap.Addr().Unmap().WithZone("") // ::ffff:127.0.0.1 и fe80::1%eth0 — тот же адрес
	for _, p := range noEgress {
		if p.Contains(ip) {
			return errEgressDenied
		}
	}
	return nil
}

const (
	// §4: ответ на невалидный AUTH — как у idle HTTP keep-alive: не сразу и не через 30 с.
	authIdle   = 2 * time.Second
	ratePerMin = 30               // как limit_req у nginx: новых соединений с IP в минуту
	rateTTL    = 10 * time.Minute // запись без обращений столько — удаляем из карты
	rateSweep  = time.Minute      // как часто подметаем карту
	writeWait  = 5 * time.Second  // запись ответа-ошибки
)

// limiter — токен-бакет на IP. Первый залп с адреса не наказываем: бакет полный.
type limiter struct {
	mu   sync.Mutex
	m    map[string]*bucket
	rate float64 // токенов в секунду
	cap  float64
	last time.Time
}

type bucket struct {
	tok  float64
	seen time.Time
}

func newLimiter(perMin int) *limiter {
	return &limiter{m: make(map[string]*bucket), rate: float64(perMin) / 60, cap: float64(perMin)}
}

func (l *limiter) allow(addr net.Addr) bool {
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		ip = addr.String()
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[ip]
	if b == nil {
		b = &bucket{tok: l.cap}
		l.m[ip] = b
	}
	b.tok = min(l.cap, b.tok+now.Sub(b.seen).Seconds()*l.rate)
	b.seen = now
	if now.Sub(l.last) > rateSweep { // иначе карта растёт на каждый новый адрес
		for k, v := range l.m {
			if now.Sub(v.seen) > rateTTL {
				delete(l.m, k)
			}
		}
		l.last = now
	}
	if b.tok < 1 {
		return false
	}
	b.tok--
	return true
}

// errBody — тело дефолтной страницы ошибки nginx.
func errBody(code int, status string) []byte {
	return fmt.Appendf(nil, "<!doctype html><html><head><title>%d %s</title></head><body>"+
		"<center><h1>%d %s</h1></center><hr><center>nginx</center></body></html>\n",
		code, status, code, status)
}

// errPage — полный ответ в формате nginx: без Server и без трейсов.
func errPage(code int, status, extra string) []byte {
	body := errBody(code, status)
	return fmt.Appendf(nil, "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"+
		"Date: %s\r\nX-Content-Type-Options: nosniff\r\n%sConnection: close\r\n\r\n%s",
		code, status, len(body), time.Now().UTC().Format(http.TimeFormat), extra, body)
}
