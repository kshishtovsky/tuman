// Пакет route — split-tunnel по цели: домен, IP-подсеть, порт.
// Приложение клиент не различает (SOCKS5 его не знает), поэтому только цель.
package route

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Action — что делать с потоком.
// Нулевое значение — Tunnel: забытый Action не уводит трафик мимо туннеля.
type Action int

const (
	Tunnel Action = iota
	Direct        // напрямую, мимо туннеля
	Block         // запретить
)

func (a Action) String() string {
	switch a {
	case Direct:
		return "direct"
	case Block:
		return "block"
	}
	return "tunnel"
}

func parseAction(s string) (Action, error) {
	switch s {
	case "tunnel":
		return Tunnel, nil
	case "direct":
		return Direct, nil
	case "block":
		return Block, nil
	}
	return Tunnel, fmt.Errorf("route: неизвестное действие %q (direct|tunnel|block)", s)
}

// PortRange — включительно.
type PortRange struct{ From, To int }

// Rule — одно правило. Domains и CIDRs — ИЛИ; Ports — дополнительный фильтр.
// Правило без Domains и CIDRs срабатывает по одному порту.
type Rule struct {
	Domains []string // "example.com" или "*.example.com" — суффикс
	CIDRs   []string // "5.255.0.0/18", "2001:db8::/32"
	Ports   []PortRange
	Action  Action
}

// cacheMax — потолок кеша решений; правила статичны, TTL не нужен.
const cacheMax = 10_000

// Table — скомпилированные правила и кеш решений.
type Table struct {
	rules []rule
	mu    sync.RWMutex
	cache map[key]Action
}

type rule struct {
	action Action
	doms   []string // суффиксы в нижнем регистре, без "*."
	cidrs  []*net.IPNet
	ports  []PortRange
}

// key — host:port структурой: склейка строки аллоцировала бы на горячем пути.
type key struct {
	host string
	port int
}

// New проверяет и компилирует правила; порядок сохраняется (первое совпадение сверху).
func New(rules []Rule) (*Table, error) {
	t := &Table{rules: make([]rule, 0, len(rules))}
	for i, r := range rules {
		cr := rule{action: r.Action, ports: r.Ports}
		for _, d := range r.Domains {
			d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
			d = strings.TrimPrefix(d, "*.")
			if d == "" {
				return nil, fmt.Errorf("правило %d: пустой домен", i)
			}
			cr.doms = append(cr.doms, d)
		}
		for _, s := range r.CIDRs {
			_, n, err := net.ParseCIDR(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("правило %d: cidr %q: %w", i, s, err)
			}
			cr.cidrs = append(cr.cidrs, n)
		}
		for _, p := range r.Ports {
			if p.From < 1 || p.To > 65535 || p.From > p.To {
				return nil, fmt.Errorf("правило %d: порты %d-%d", i, p.From, p.To)
			}
		}
		t.rules = append(t.rules, cr)
	}
	return t, nil
}

// Decide — действие для цели. Попадание в кеш не аллоцирует.
func (t *Table) Decide(host string, port int) Action {
	host = normHost(host)
	k := key{host, port}
	t.mu.RLock()
	a, ok := t.cache[k]
	t.mu.RUnlock()
	if ok {
		return a
	}
	a = t.decide(host, port)
	t.mu.Lock()
	if t.cache == nil {
		t.cache = make(map[key]Action, 64)
	}
	if len(t.cache) < cacheMax { // переполнение — просто дальше не кешируем
		t.cache[k] = a
	}
	t.mu.Unlock()
	return a
}

func (t *Table) decide(host string, port int) Action {
	// Резолва нет намеренно: резолв домена на клиенте — утечка DNS.
	ip := net.ParseIP(host)
	for i := range t.rules {
		if t.rules[i].match(host, ip, port) {
			return t.rules[i].action
		}
	}
	return Tunnel
}

func (r *rule) match(host string, ip net.IP, port int) bool {
	if len(r.ports) > 0 {
		ok := false
		for _, p := range r.ports {
			if port >= p.From && port <= p.To {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.doms) == 0 && len(r.cidrs) == 0 {
		return true // правило только по порту
	}
	if ip != nil {
		for _, n := range r.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range r.doms {
		if suffix(host, d) {
			return true
		}
	}
	return false
}

// suffix — host равен d или заканчивается на ".d": иначе notexample.com
// попал бы в example.com.
func suffix(host, d string) bool {
	i := len(host) - len(d)
	if i < 0 || host[i:] != d {
		return false
	}
	return i == 0 || host[i-1] == '.'
}

// normHost убирает точку в конце и приводит к нижнему регистру,
// не аллоцируя, если хост уже в нормальной форме.
func normHost(h string) string {
	h = strings.TrimSuffix(h, ".")
	for i := 0; i < len(h); i++ {
		if c := h[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(h)
		}
	}
	return h
}
