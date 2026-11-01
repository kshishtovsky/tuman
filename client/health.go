package client

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Эпизод ошибок — пауза 30 с; каждый следующий эпизод удваивает её до 60 с:
// дольше держать сервер выключенным нельзя, канал обязан ожить за секунды (NFR-12).
const (
	coolDownBase = 30 * time.Second
	pauseMax     = 60 * time.Second
)

type epState struct {
	ok, fail int           // всего успешных и неудачных установлений
	failing  bool          // текущий эпизод ошибок уже учтён
	dial     time.Duration // время последнего успешного установления
	cool     time.Duration // текущая длина паузы
	until    time.Time     // до этого момента ендпоинт не трогаем
}

// health — состояние ендпоинтов по индексу; адресов не хранит (NFR-11: логи без адресов).
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
	return &health{st: make([]epState, n), now: time.Now, base: base, max: min(10*base, pauseMax)}
}

// ok — установление удалось: эпизод ошибок и пауза сбрасываются.
func (h *health) ok(i int, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.st[i]
	s.ok++
	s.failing, s.cool, s.until, s.dial = false, 0, time.Time{}, d
}

// fail — ошибка установления. Слоты делят ендпоинт, поэтому один сбой даёт
// пачку вызовов: пауза (и её удвоение) считается один раз за эпизод, иначе
// блип в полторы секунды с 4 слотами выключал ендпоинт на 240 с.
func (h *health) fail(i int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.st[i]
	s.fail++
	if s.failing {
		return
	}
	s.failing = true
	switch {
	case s.cool == 0:
		s.cool = h.base
	default:
		s.cool = min(2*s.cool, h.max)
	}
	s.until = h.now().Add(s.cool)
}

// usable: ендпоинт не в паузе; если в паузе — сколько ещё ждать.
func (h *health) usable(i int) (bool, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.st[i]
	if rem := s.until.Sub(h.now()); rem > 0 {
		return false, rem
	}
	s.failing = false // пауза истекла: следующая ошибка — новый эпизод
	return true, 0
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
