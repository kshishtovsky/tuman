// Package shaper — форма трафика под выбранный эталон (docs/03-system-design.md §3).
//
// Обёртка над io.ReadWriter: mux.New принимает любое io.ReadWriter, поэтому
// шейпер вставляется между TLS-соединением и mux без правок mux.
package shaper

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/kshishtovsky/tuman/proto"
)

type Profile string

const (
	Off    Profile = "off"
	Browse Profile = "browse"
	Video  Profile = "video"
	Bulk   Profile = "bulk"
	Voice  Profile = "voice"
)

const (
	headerLen    = 8
	earlyLimit   = 64 << 10             // паддинг и коалесинг только в первые 64 КБ полезной нагрузки
	coalesceWait = 2 * time.Millisecond // сколько мелкая запись ждёт следующую
	cadence      = 20 * time.Millisecond
	cadenceSlack = 3 * time.Millisecond
)

var (
	errDeadline = errors.New("shaper: inner не поддерживает SetDeadline")
	zeros       [proto.MaxPayload]byte // источник байт для PAD, только чтение
)

// form — целевая форма: окно размера записи [lo, hi], пол в начале сессии, каденция voice.
type form struct {
	lo, hi int
	floor  int
	voice  bool
}

var forms = map[Profile]form{
	Browse: {lo: 200, hi: 1500, floor: 700},   // HTTP/2 к обычному сайту
	Video:  {lo: 1024, hi: 1400, floor: 1024}, // сегментированное видео
	Bulk:   {lo: 0, hi: 0, floor: 700},        // крупные записи, паддинга нет
	Voice:  {voice: true},                     // 20 мс каденция, без паддинга
}

// Valid — проверка имени профиля из конфига.
func (p Profile) Valid() bool {
	if p == Off {
		return true
	}
	_, ok := forms[p]
	return ok
}

type Config struct {
	Profile Profile
}

// Shaper реализует io.ReadWriter поверх inner.
type Shaper struct {
	inner io.ReadWriter
	f     form

	mu   sync.Mutex // сериализует записи из mux и фоновую добивку
	pend []byte     // мелкие записи начала сессии до коалесинга
	out  []byte     // текущая запись: коалесинг + PAD
	wake chan struct{}
	done chan struct{}
	stop bool
	err  error

	sent, padded int64 // полезные и паддинговые байты за сессию
	next         time.Time
	rnd          uint64
}

// New — профиль Off даёт сквозной пропуск без горутин и блокировок.
func New(inner io.ReadWriter, cfg Config) *Shaper {
	f := forms[cfg.Profile]
	s := &Shaper{
		inner: inner,
		f:     f,
		pend:  make([]byte, 0, 2048),
		out:   make([]byte, 0, 2048),
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
		rnd:   uint64(time.Now().UnixNano()) | 1,
	}
	if f.floor > 0 {
		go s.finish() // добивка накопленного, если следующей записи нет
	}
	return s
}

func (s *Shaper) Read(p []byte) (int, error) { return s.inner.Read(p) }

func (s *Shaper) Write(p []byte) (int, error) {
	if s.f == (form{}) {
		return s.inner.Write(p)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if hasUrgent(p) {
		// URGENT важнее формы: без задержки, коалесинга и паддинга.
		return s.raw(p)
	}
	if s.f.voice {
		return s.pace(p)
	}
	if s.sent < earlyLimit {
		return s.early(p)
	}
	return s.raw(p)
}

// raw — сквозной пропуск; недочитанный кадр из накопленного уходит первым.
func (s *Shaper) raw(p []byte) (int, error) {
	if len(s.pend) > 0 {
		s.pend = append(s.pend, p...)
		s.sent += int64(len(s.pend))
		_, err := s.inner.Write(s.pend)
		s.pend = s.pend[:0]
		return len(p), err
	}
	s.sent += int64(len(p))
	_, err := s.inner.Write(p)
	return len(p), err
}

// early — начало сессии: отдаём только целые кадры, мелкую запись копим,
// остальное добиваем PAD-кадрами до окна профиля.
func (s *Shaper) early(p []byte) (int, error) {
	s.pend = append(s.pend, p...)
	n := s.aligned()
	if n == 0 {
		return len(p), nil // кадра ещё нет целиком
	}
	if n < s.f.floor {
		if n == len(s.pend) {
			s.arm() // ждать больше нечего: добивка по таймеру
		}
		return len(p), nil
	}
	s.sent += int64(n)
	if s.f.hi > 0 && n < s.f.hi {
		s.out = append(s.out[:0], s.pend[:n]...)
		s.pad()
		if _, err := s.inner.Write(s.out); err != nil {
			return 0, err
		}
	} else if _, err := s.inner.Write(s.pend[:n]); err != nil {
		return 0, err
	}
	s.keep(n)
	return len(p), nil
}

// arm — просьба фоновой добивке сбросить накопленное по таймеру.
func (s *Shaper) arm() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// keep оставляет в pend хвост после отданного префикса.
func (s *Shaper) keep(n int) {
	copy(s.pend, s.pend[n:])
	s.pend = s.pend[:len(s.pend)-n]
}

// aligned — длина префикса pend по границе кадра. Неразбираемый поток
// (длина кадра указывает за пределы TMN/1) отдаём целиком, чтобы не встать.
func (s *Shaper) aligned() int {
	b := s.pend
	i := 0
	for len(b)-i >= headerLen {
		n := headerLen + int(b[i+4])<<8 + int(b[i+5])
		if len(b)-i < n {
			break
		}
		i += n
	}
	if i == 0 && len(b) > headerLen+proto.MaxPayload {
		return len(b)
	}
	return i
}

// pad добивает s.out PAD-кадрами до окна профиля: не более 2× полезной нагрузки
// на запись и не более 20 % отданного объёма (D ≤ P/4).
func (s *Shaper) pad() {
	framed := len(s.out)
	payload := framed - headerLen*frames(s.out) // потолок считается по полезной нагрузке, без заголовков
	lo, hi := s.f.lo, s.f.hi
	if lo < s.f.floor {
		lo = s.f.floor
	}
	if lim := 2 * payload; lo > lim {
		lo = lim
	}
	if lo > hi {
		return
	}
	t := lo
	if hi > lo {
		t += int(s.rand() % uint64(hi-lo+1))
	}
	if t > 2*payload {
		t = 2 * payload
	}
	if t > hi {
		t = hi
	}
	if t-framed < headerLen || s.padded*4 > s.sent {
		return // места под заголовок PAD нет либо бюджет выбран
	}
	for len(s.out) < t {
		m := t - len(s.out) - headerLen
		if m > proto.MaxPayload {
			m = proto.MaxPayload
		}
		var hb [headerLen]byte
		proto.Header{Type: proto.TypePad, Length: uint16(m)}.MarshalTo(hb[:])
		s.out = append(s.out, hb[:]...)
		s.out = append(s.out, zeros[:m]...)
	}
	s.padded += int64(t - framed)
}

// frames — число кадров в потоке (он уже выровнен по границам).
func frames(b []byte) int {
	n := 0
	for len(b) >= headerLen {
		n++
		b = b[headerLen+int(b[4])<<8+int(b[5]):]
	}
	return n
}

// flush отдаёт накопленное: целые кадры, с добивкой до окна профиля если хвоста нет.
func (s *Shaper) flush() error {
	n := s.aligned()
	if n == 0 {
		return nil
	}
	s.sent += int64(n)
	if n == len(s.pend) && s.f.hi > 0 && n < s.f.hi {
		s.out = append(s.out[:0], s.pend...)
		s.pad()
		if _, err := s.inner.Write(s.out); err != nil {
			s.err = err
			return err
		}
	} else if _, err := s.inner.Write(s.pend[:n]); err != nil {
		s.err = err
		return err
	}
	s.keep(n)
	return nil
}

// pace — каденция voice: 20 мс между записями, при отставании больше допуска — ресинхронизация.
func (s *Shaper) pace(p []byte) (int, error) {
	now := time.Now()
	if s.next.IsZero() || now.Sub(s.next) > cadenceSlack {
		s.next = now
	}
	if d := s.next.Sub(now); d > 0 {
		time.Sleep(d)
	}
	s.next = s.next.Add(cadence)
	s.sent += int64(len(p))
	if _, err := s.inner.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// finish сбрасывает накопленное по таймеру; спит, пока накапливать нечего.
func (s *Shaper) finish() {
	t := time.NewTimer(time.Hour)
	if !t.Stop() {
		<-t.C
	}
	for {
		select {
		case <-s.done:
			return
		case <-s.wake:
		}
		t.Reset(coalesceWait)
		select {
		case <-t.C:
		case <-s.done:
			return
		}
		s.mu.Lock()
		if !s.stop {
			s.flush()
		}
		s.mu.Unlock()
	}
}

func (s *Shaper) Close() error {
	if s.f == (form{}) {
		return s.closeInner()
	}
	s.mu.Lock()
	err := s.flush()
	if len(s.pend) > 0 {
		s.inner.Write(s.pend) // недочитанный кадр: отдаём как есть
		s.pend = s.pend[:0]
	}
	if !s.stop {
		s.stop = true
		close(s.done)
	}
	s.mu.Unlock()
	if cerr := s.closeInner(); err == nil {
		err = cerr
	}
	return err
}

func (s *Shaper) closeInner() error {
	if c, ok := s.inner.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (s *Shaper) SetDeadline(t time.Time) error {
	if d, ok := s.inner.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return errDeadline
}

// hasUrgent — в p есть кадр с флагом URGENT. Неполный хвост не разбираем.
func hasUrgent(p []byte) bool {
	for len(p) >= headerLen {
		if p[1]&proto.FlagUrgent != 0 {
			return true
		}
		n := headerLen + int(p[4])<<8 + int(p[5])
		if n > len(p) {
			return false
		}
		p = p[n:]
	}
	return false
}

// rand — xorshift64: разброс размеров без аллокаций.
func (s *Shaper) rand() uint64 {
	s.rnd ^= s.rnd << 13
	s.rnd ^= s.rnd >> 7
	s.rnd ^= s.rnd << 17
	return s.rnd
}
