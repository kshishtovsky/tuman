// Package shaper — форма трафика под выбранный эталон (docs/03-system-design.md §3).
//
// Обёртка над io.ReadWriter: mux.New принимает любое io.ReadWriter, поэтому
// шейпер вставляется между TLS-соединением и mux без правок mux.
//
// Одна запись на проводе = один inner.Write = одна TLS-запись. Размер цели
// берётся из замеров живого HTTPS; кадр TMN/1 через границу записи не режем,
// поэтому цель — желаемый размер, а не гарантия.
package shaper

import (
	"errors"
	"io"
	"math"
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
	nBins        = 9
	coalesceWait = 2 * time.Millisecond // сколько ждём следующую запись, прежде чем отдать короткую
	cadence      = 20 * time.Millisecond
	cadenceSlack = 3 * time.Millisecond
	burstMax     = 8                      // записей подряд в одной пачке
	idleGap      = 5 * time.Millisecond   // тишина дольше — это новая пачка, а не передача
	thinkMedian  = 150 * time.Millisecond // медиана паузы между пачками
	thinkMin     = 20 * time.Millisecond
	thinkMax     = 3 * time.Second        // хвост паузы
	thinkWait    = 400 * time.Millisecond // дольше не выжидаем: задержка отклика важнее
	talkspurtMin = time.Second
	talkspurtMax = 3 * time.Second
	dtxMin       = 200 * time.Millisecond
	dtxMax       = 800 * time.Millisecond
)

var (
	errDeadline = errors.New("shaper: inner не поддерживает SetDeadline")
)

// bin — корзина размеров записи server->client.
type bin struct{ lo, hi int }

var bins = [nBins]bin{
	{0, 256}, {257, 512}, {513, 1024}, {1025, 1536}, {1537, 2048},
	{2049, 4096}, {4097, 8192}, {8193, 12288}, {12289, 16384},
}

// Доли записей по корзинам, %: гистограмма живого HTTPS (github.com,
// www.cloudflare.com, speed.cloudflare.com, en.wikipedia.org), вес хостов равный.
var (
	distBrowse = [nBins]float32{26, 6, 1, 34, 3, 5, 17, 4, 4}
	distBulk   = [nBins]float32{1, 1, 2, 6, 4, 16, 25, 22, 23} // скачивание: почти всё крупным
)

// sets — четыре набора весов: медленный дрейф в пределах ±15 %, чтобы форма
// не была одной и той же подписью неделями.
var sets = [4][nBins]float32{
	{1, 1, 1, 1, 1, 1, 1, 1, 1},
	{.85, .9, 1, 1.15, 1.15, 1.1, .9, .85, .85},     // больше средних
	{1.15, 1.15, 1.1, .85, .9, .95, 1.1, 1.15, 1.1}, // больше мелких
	{.9, .85, .9, 1.1, 1.1, 1.15, 1.15, 1.05, 1.15}, // больше крупных
}

// form — форма записи: окно размера (video), веса корзин (browse/bulk),
// talkspurt (voice). Нулевая form — профиль Off.
type form struct {
	lo, hi int // окно размера; 0/0 — размер по весам
	voice  bool
	w      *[nBins]float32 // веса корзин
}

var forms = map[Profile]form{
	Browse: {w: &distBrowse},
	Video:  {lo: 1024, hi: 1400}, // сегментированное видео
	Bulk:   {w: &distBulk},       // паддинга нет: только коалесинг
	Voice:  {voice: true},        // talkspurt 20 мс, потом DTX
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
	// Seed задаёт форму: 0 — из текущего времени. Один Seed даёт одну форму
	// до смены недели (медленный дрейф весов).
	Seed uint64
}

// Shaper реализует io.ReadWriter поверх inner.
type Shaper struct {
	inner io.ReadWriter
	f     form

	mu   sync.Mutex // сериализует записи из mux и фоновую добивку
	pend []byte     // накопленные кадры до целой записи
	wake chan struct{}
	done chan struct{}
	stop bool
	err  error

	sent, padded int64          // полезные и паддинговые байты за сессию
	cum          [nBins]float64 // CDF выбранного набора весов
	tgt          int            // цель текущей записи; 0 — нужна новая
	rnd          uint64

	last  time.Time // последний Write: тишина после него — новая пачка
	next  time.Time // раньше этого момента пачку не начинаем
	burst int       // записей в текущей пачке
	batch int       // сколько записей в пачке (1..burstMax)
	talk  time.Time // конец текущего talkspurt (voice)
}

// New — профиль Off даёт сквозной пропуск без горутин и блокировок.
func New(inner io.ReadWriter, cfg Config) *Shaper { return newAt(inner, cfg, time.Now()) }

// newAt — New с инъекцией времени: недельный бакет и набор весов считаются
// от t, чтобы тест не зависел от календаря.
func newAt(inner io.ReadWriter, cfg Config, t time.Time) *Shaper {
	seed := cfg.Seed
	if seed == 0 {
		seed = uint64(t.UnixNano())
	}
	s := &Shaper{
		inner: inner,
		f:     forms[cfg.Profile],
		pend:  make([]byte, 0, 2048),
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
		rnd:   seed | 1, // xorshift не вырождается в ноль
	}
	week := uint64(t.Unix() / (7 * 24 * 3600))
	s.cum = cdf(s.f, (mix(seed)+week)%uint64(len(sets)))
	s.batch = 1 + int(s.rand()%burstMax)
	if s.f.voice {
		s.talk = t.Add(s.talkspurt())
	} else if s.f != (form{}) {
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
	s.think(time.Now())
	// Быстрый путь: цель не больше кадра — копировать в pend незачем.
	if len(s.pend) == 0 && oneFrame(p) {
		if s.tgt == 0 {
			s.tgt = s.draw()
		}
		if s.tgt <= len(p) {
			s.sent += int64(len(p))
			s.tgt = 0
			_, err := s.inner.Write(p)
			s.record()
			if err != nil {
				s.err = err
			}
			return len(p), err
		}
	}
	s.pend = append(s.pend, p...)
	if err := s.emit(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// raw — сквозной пропуск; недочитанный кадр из накопленного уходит первым.
func (s *Shaper) raw(p []byte) (int, error) {
	if len(s.pend) > 0 {
		s.pend = append(s.pend, p...)
		s.sent += int64(len(s.pend))
		_, err := s.inner.Write(s.pend)
		s.pend = s.pend[:0]
		s.tgt = 0
		return len(p), err
	}
	s.sent += int64(len(p))
	_, err := s.inner.Write(p)
	return len(p), err
}

// emit отдаёт записи по цели. Границы кадров не соблюдаются намеренно: mux
// читает поток байт (io.ReadFull по заголовку), а границ TLS-записей не видит,
// поэтому кадр можно разрезать между записями. Без этого цели мельче кадра
// (26 % весов) недостижимы и все они сваливаются в одну корзину — ровно тот
// отпечаток, который шейпер и должен убирать. last — ждать больше нечего
// (таймер, Close): отдаём что есть.
func (s *Shaper) emit(last bool) error {
	for len(s.pend) > 0 {
		if s.tgt == 0 {
			s.tgt = s.draw()
		}
		if len(s.pend) < s.tgt && !last {
			s.arm() // цель не набрана: ждём следующую запись или таймер
			return nil
		}
		k := s.tgt
		if k > len(s.pend) {
			k = len(s.pend)
		}
		if err := s.write(k); err != nil {
			return err
		}
	}
	return nil
}

// write — одна запись из k байт pend. Паддинга нет: размер задаёт цель, и
// добивать до неё незачем — это только тратило бы полосу.
func (s *Shaper) write(k int) error {
	s.sent += int64(k)
	if _, err := s.inner.Write(s.pend[:k]); err != nil {
		s.err = err
		return err
	}
	s.keep(k)
	s.tgt = 0
	s.record()
	return nil
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

// oneFrame — p это ровно один кадр TMN/1.
func oneFrame(p []byte) bool {
	return len(p) >= headerLen && len(p) <= headerLen+proto.MaxPayload &&
		headerLen+int(p[4])<<8+int(p[5]) == len(p)
}

// think — пауза между пачками: выжидаем остаток, только если отправитель
// действительно замолк. Непрерывную передачу не тормозим — там паузы нет.
func (s *Shaper) think(now time.Time) {
	if !s.last.IsZero() && now.Sub(s.last) > idleGap {
		s.burst = 0
		if d := s.next.Sub(now); d > 0 {
			if d > thinkWait {
				d = thinkWait // хвост паузы не выжидаем: отклик важнее
			}
			time.Sleep(d)
		}
	}
	s.last = now
}

// record — учёт пачки: после 1..burstMax записей подряд ставим паузу.
func (s *Shaper) record() {
	if s.burst++; s.burst >= s.batch {
		s.next = time.Now().Add(s.pause())
		s.burst, s.batch = 0, 1+int(s.rand()%burstMax)
	}
}

// pace — talkspurt: 20 мс каденция; после 1-3 с речи — DTX-пауза 200-800 мс.
func (s *Shaper) pace(p []byte) (int, error) {
	now := time.Now()
	if !now.Before(s.talk) {
		time.Sleep(s.dtx())
		now = time.Now()
		s.talk = now.Add(s.talkspurt())
		s.next = now
	}
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
			s.emit(true)
		}
		s.mu.Unlock()
	}
}

func (s *Shaper) Close() error {
	if s.f == (form{}) {
		return s.closeInner()
	}
	s.mu.Lock()
	var err error
	if !s.stop {
		err = s.emit(true)
	}
	if len(s.pend) > 0 {
		// Остаток идёт через write(), а не сырым Write: иначе последняя
		// запись выпадала бы из формы и из счётчиков.
		s.tgt = len(s.pend)
		_ = s.write(len(s.pend))
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

// cdf — накопленные веса набора; нули — форма с фиксированным окном.
func cdf(f form, set uint64) [nBins]float64 {
	var c [nBins]float64
	if f.w == nil {
		return c
	}
	var acc float64
	for i, w := range f.w {
		acc += float64(w) * float64(sets[set][i])
		c[i] = acc
	}
	return c
}

// draw — цель размера записи: инверсия CDF по существующему xorshift.
func (s *Shaper) draw() int {
	if s.cum[nBins-1] == 0 { // фиксированное окно
		return s.f.lo + int(s.rand()%uint64(s.f.hi-s.f.lo+1))
	}
	r := s.unit() * s.cum[nBins-1]
	i := 0
	for i < nBins-1 && r >= s.cum[i] {
		i++
	}
	b := bins[i]
	return b.lo + int(s.rand()%uint64(b.hi-b.lo+1))
}

// pause — think-time: log-normal, медиана ~150 мс, хвост до 3 с.
func (s *Shaper) pause() time.Duration {
	z := 0.0 // сумма четырёх равномерных ≈ нормальное
	for i := 0; i < 4; i++ {
		z += s.unit()
	}
	p := float64(thinkMedian) * math.Exp(0.8*(z-2)*1.732)
	if p < float64(thinkMin) {
		p = float64(thinkMin)
	}
	if p > float64(thinkMax) {
		p = float64(thinkMax)
	}
	return time.Duration(p)
}

func (s *Shaper) talkspurt() time.Duration {
	span := uint64((talkspurtMax - talkspurtMin) / time.Millisecond)
	return talkspurtMin + time.Duration(s.rand()%span)*time.Millisecond
}

func (s *Shaper) dtx() time.Duration {
	span := uint64((dtxMax - dtxMin) / time.Millisecond)
	return dtxMin + time.Duration(s.rand()%span)*time.Millisecond
}

// unit — равномерное [0,1) из того же xorshift.
func (s *Shaper) unit() float64 { return float64(s.rand()>>11) / float64(uint64(1)<<53) }

// mix — финализатор splitmix64: разводит близкие Seed по разным фазам.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
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
