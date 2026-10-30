package client

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// 2 ошибки подряд — пауза 30 с; каждый следующий провал удваивает её до 5 минут (G3).
const (
	failLimit    = 2
	coolDownBase = 30 * time.Second
)

type epState struct {
	ok, fail int           // всего успешных и неудачных установлений
	streak   int           // ошибок подряд
	dial     time.Duration // время последнего успешного установления
	cool     time.Duration // текущая длина паузы
	until    time.Time     // до этого момента ендпоинт не трогаем
}

// health — состояние ендпоинтов по индексу; адресов не хранит (FR-11: логи без адресов).
type health struct {
	mu   sync.Mutex
	st   []epState
	now  func() time.Time // тесты подменяют часы
	base time.Duration
	max  time.Duration
}

func newHealth(n int, base time.Duration) *health {
	if base <= 0 {
		base = coolDownBase
	}
	return &health{st: make([]epState, n), now: time.Now, base: base, max: 10 * base}
}

// ok — установление удалось: серия ошибок и пауза сбрасываются.
func (h *health) ok(i int, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.st[i]
	s.ok++
	s.streak, s.cool, s.until, s.dial = 0, 0, time.Time{}, d
}

// fail — ошибка установления; после failLimit подряд ендпоинт уходит в паузу.
func (h *health) fail(i int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.st[i]
	s.fail++
	s.streak++
	if s.streak < failLimit {
		return
	}
	switch {
	case s.cool == 0:
		s.cool = h.base
	default:
		s.cool *= 2
		if s.cool > h.max {
			s.cool = h.max
		}
	}
	s.until = h.now().Add(s.cool)
}

// usable: ендпоинт не в паузе; если в паузе — сколько ещё ждать.
func (h *health) usable(i int) (bool, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rem := h.st[i].until.Sub(h.now())
	return rem <= 0, rem
}

// next — следующий за from доступный по кругу; если доступных нет — тот,
// у кого пауза кончится раньше (лучше попробовать, чем стоять).
func (h *health) next(from int) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.st)
	now := h.now()
	best := -1
	for k := 1; k <= n; k++ {
		i := (from + k) % n
		if !now.Before(h.st[i].until) {
			return i
		}
		if best < 0 || h.st[i].until.Before(h.st[best].until) {
			best = i
		}
	}
	return best
}

// String — строки вида ep=0 ok=2 fail=1 cool=12s: только индексы, без адресов.
func (h *health) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	var b strings.Builder
	for i, s := range h.st {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "ep=%d ok=%d fail=%d dial=%s", i, s.ok, s.fail, s.dial.Round(time.Millisecond))
		if rem := s.until.Sub(now); rem > 0 {
			fmt.Fprintf(&b, " cool=%s", rem.Round(time.Second))
		}
	}
	return b.String()
}
