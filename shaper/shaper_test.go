package shaper

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// sink — приёмник записей: размеры, паддинг и склеенный поток кадров.
type sink struct {
	mu    sync.Mutex
	quiet bool // не копить размеры/байты (для теста аллокаций)
	sizes []int
	buf   []byte
	n     int64
}

func (s *sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.n += int64(len(p))
	if !s.quiet {
		s.sizes = append(s.sizes, len(p))
		s.buf = append(s.buf, p...)
	}
	s.mu.Unlock()
	return len(p), nil
}

func (s *sink) Read(p []byte) (int, error) { return 0, io.EOF }

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sizes)
}

func (s *sink) last() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sizes[len(s.sizes)-1]
}

// stream — полезные байты (без PAD) и суммарный паддинг всего потока.
func stream(t *testing.T, snk *sink) ([]byte, int) {
	t.Helper()
	snk.mu.Lock()
	b := snk.buf
	snk.mu.Unlock()
	var data []byte
	var pad int
	for len(b) > 0 {
		if len(b) < headerLen {
			t.Fatalf("обрыв заголовка: %d байт", len(b))
		}
		n := headerLen + int(b[4])<<8 + int(b[5])
		if n > len(b) {
			t.Fatalf("длина кадра %d больше остатка %d", n, len(b))
		}
		if b[0] == proto.TypePad {
			pad += int(b[4])<<8 + int(b[5])
		} else {
			data = append(data, b[headerLen:n]...)
		}
		b = b[n:]
	}
	return data, pad
}

// records — полезные байты и байты паддинга по каждой записи (поток выровнен по кадрам).
// records разбирает ВЕСЬ отданный поток как последовательность кадров TMN/1.
// Границы TLS-записей кадры намеренно рвут (mux читает поток байт), поэтому
// проверять надо поток: он обязан остаться разбираемым, а суммы — сойтись.
func records(t *testing.T, snk *sink) (pay, pad, data int) {
	t.Helper()
	snk.mu.Lock()
	defer snk.mu.Unlock()
	for _, size := range snk.sizes {
		data += size
	}
	b := snk.buf
	for len(b) > 0 {
		if len(b) < headerLen {
			t.Fatalf("поток оборван на заголовке: %d байт", len(b))
		}
		n := headerLen + int(b[4])<<8 + int(b[5])
		if n > len(b) {
			t.Fatalf("длина кадра %d больше остатка потока %d", n, len(b))
		}
		if b[0] == proto.TypePad {
			pad += int(b[4])<<8 + int(b[5])
		} else {
			pay += int(b[4])<<8 + int(b[5])
		}
		b = b[n:]
	}
	return pay, pad, data
}

func dataFrame(n int, flags uint8) []byte {
	b := make([]byte, headerLen+n)
	proto.Header{Type: proto.TypeData, Stream: 1, Flags: flags, Length: uint16(n)}.MarshalTo(b)
	for i := headerLen; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}

func TestOffPassThrough(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Off})
	defer s.Close()
	for i := 0; i < 5; i++ {
		if _, err := s.Write(dataFrame(100, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if len(snk.sizes) != 5 || snk.sizes[0] != 108 {
		t.Fatalf("off должен пропускать записи как есть: %v", snk.sizes)
	}
}

// TestRecordHistogram — форма выходного потока: размеры записей покрывают и
// мелкие (управляющие), и крупные (коалесинг) корзины живого HTTPS.
func TestRecordHistogram(t *testing.T) {
	snk := &sink{}
	s := newAt(snk, Config{Profile: Browse, Seed: 42}, time.Unix(2810*weekSec, 0))
	defer s.Close()
	rec, ctl := dataFrame(proto.MaxPayload-8, 0), dataFrame(40, 0)
	for i := 0; i < 3000; i++ { // ~4 МБ
		p := rec
		if i%40 == 0 {
			p = ctl // управляющие кадры дают мелкие записи
		}
		if _, err := s.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	snk.mu.Lock()
	sizes := snk.sizes
	snk.mu.Unlock()
	var hist [nBins]int
	var big, small, total, in int
	for i := 0; i < 3000; i++ {
		n := len(rec)
		if i%40 == 0 {
			n = len(ctl)
		}
		in += n
	}
	for _, n := range sizes {
		total += n
		if n <= 512 {
			small++
		}
		if n > 8192 {
			big++
		}
		for i, b := range bins {
			if n >= b.lo && n <= b.hi {
				hist[i]++
			}
		}
	}
	// Критерий — «весь вход дошёл до inner», а не «больше 4 МиБ»: вход
	// подбирается из кадров, и фиксированный порог врал о самом тесте.
	if total != in {
		t.Fatalf("через шейпер прошло %d байт из %d", total, in)
	}
	used := 0
	for _, c := range hist {
		if c > 0 {
			used++
		}
	}
	if used < 4 {
		t.Fatalf("занято %d корзин из %d: %v", used, nBins, hist)
	}
	if big == 0 {
		t.Fatalf("нет записей > 8192: %v", hist)
	}
	if small == 0 {
		t.Fatalf("нет мелких записей ≤ 512: %v", hist)
	}
	t.Logf("записей %d, корзины %v, >8192: %d, ≤512: %d", len(sizes), hist, big, small)
}

// weekSec — недельный бакет дрейфа формы.
const weekSec = 7 * 24 * 3600

// run — прогнать n кадров через шейпер и вернуть размеры записей.
func run(t *testing.T, seed uint64, at time.Time, n int) []int {
	t.Helper()
	snk := &sink{}
	s := newAt(snk, Config{Profile: Browse, Seed: seed}, at)
	rec := dataFrame(proto.MaxPayload-8, 0)
	for i := 0; i < n; i++ {
		if _, err := s.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	snk.mu.Lock()
	defer snk.mu.Unlock()
	return append([]int(nil), snk.sizes...)
}

func eq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSeedDeterminism — один Seed и один вход дают одну последовательность
// размеров; другой Seed — другую.
func TestSeedDeterminism(t *testing.T) {
	at := time.Unix(2810*weekSec, 0)
	a, b := run(t, 7, at, 200), run(t, 7, at, 200)
	if !eq(a, b) {
		t.Fatalf("один Seed дал разные размеры:\n%v\n%v", a, b)
	}
	if c := run(t, 8, at, 200); eq(a, c) {
		t.Fatal("разные Seed дали одинаковую форму")
	}
}

// TestWeeklyDrift — форма стабильна внутри недели и меняется в следующей.
func TestWeeklyDrift(t *testing.T) {
	at := time.Unix(2810*weekSec+3600, 0) // начало бакета: +48 ч не выходит за неделю
	a := run(t, 7, at, 200)
	if b := run(t, 7, at.Add(48*time.Hour), 200); !eq(a, b) {
		t.Fatal("форма изменилась внутри недели")
	}
	c := run(t, 7, at.Add(8*24*time.Hour), 200)
	if eq(a, c) {
		t.Fatal("форма не изменилась на следующей неделе")
	}
}

// TestVoiceDTX — talkspurt кончился: DTX-пауза 200-800 мс, потом снова речь.
func TestVoiceDTX(t *testing.T) {
	snk := &sink{quiet: true}
	s := New(snk, Config{Profile: Voice})
	defer s.Close()
	s.talk = time.Now() // talkspurt истёк: не ждём 1-3 с впустую
	start := time.Now()
	for i := 0; i < 8; i++ {
		if _, err := s.Write(dataFrame(200, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < dtxMin || d > dtxMax+8*cadence+50*time.Millisecond {
		t.Fatalf("DTX-пауза %v вне [%v,%v]", d, dtxMin, dtxMax)
	}
}

// TestThinkTime — пачка записей уходит без задержки, после паузы отправителя
// следующая пачка ждёт (но не дольше thinkWait).
func TestThinkTime(t *testing.T) {
	snk := &sink{quiet: true}
	s := New(snk, Config{Profile: Browse, Seed: 9})
	defer s.Close()
	start := time.Now()
	for i := 0; i < burstMax; i++ {
		if _, err := s.Write(dataFrame(proto.MaxPayload-8, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("пачка из %d записей заняла %v", burstMax, d)
	}
	// Пауза между пачками намеренно НЕ выжидается: think() спал под
	// мьютексом сессии и останавливал все потоки сразу — это и была
	// просадка скорости при множестве соединений (speedtest, браузер).
	time.Sleep(2 * idleGap) // отправитель замолк: это новая пачка
	start = time.Now()
	if _, err := s.Write(dataFrame(proto.MaxPayload-8, 0)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Millisecond {
		t.Fatalf("горячий путь задержался на %v после тишины: пауза вернулась", d)
	}
}

func TestVideoSizes(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Video})
	defer s.Close()
	for i := 0; i < 300; i++ {
		if _, err := s.Write(dataFrame(200, 0)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	records(t, snk) // поток обязан остаться разбираемым
	// Верхняя граница жёсткая: перелёт за окно виден снаружи. Нижняя —
	// мягкая: таймер обязан отдать накопленное, даже если окно не набрано,
	// иначе поток висит до следующего кадра. Таких хвостов должно быть мало.
	short := 0
	for i := range snk.sizes {
		size := snk.sizes[i]
		if size > 1400 {
			t.Fatalf("запись %d: размер %d больше окна 1400", i, size)
		}
		if size < 1024 {
			short++
		}
	}
	if short*10 > len(snk.sizes) {
		t.Fatalf("коротких записей %d из %d: больше 10 %%", short, len(snk.sizes))
	}
}

func TestBulkNoPadding(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Bulk})
	defer s.Close()
	// Объём должен перекрывать крупные цели (до 16 КиБ), иначе шейпер
	// отдаёт по таймеру огрызками и форма bulk просто не разворачивается.
	for i := 0; i < 2000; i++ {
		if _, err := s.Write(dataFrame(300, 0)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if _, pad, _ := records(t, snk); pad != 0 {
		t.Fatalf("bulk: паддинг %d байт", pad)
	}
	if len(snk.sizes) == 0 {
		t.Fatal("bulk: ни одной записи")
	}
	big := 0
	for _, n := range snk.sizes {
		if n > 4096 {
			big++
		}
	}
	// bulk копит крупные записи, но не раздувает их: мелкие доли в таблице — это
	// управляющие кадры, а не повод дробить передачу
	if big < len(snk.sizes)/2 {
		t.Fatalf("bulk: крупных записей %d из %d: %v", big, len(snk.sizes), snk.sizes)
	}
}

func TestPaddingBudget(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Browse})
	defer s.Close()
	const total = 1 << 20
	chunk := make([]byte, 1000)
	for i := 0; i < total/len(chunk); i++ {
		for j := range chunk {
			chunk[j] = byte(i + j)
		}
		if err := proto.WriteFrame(s, proto.Header{Type: proto.TypeData, Stream: 1}, chunk); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	data, sumPad := stream(t, snk)
	sumPay := len(data)
	if ratio := float64(sumPad) / float64(sumPay+sumPad); ratio > 0.20 {
		t.Fatalf("паддинг %.1f %% > 20 %%", ratio*100)
	}
}

func TestIntegrity(t *testing.T) {
	for _, pr := range []Profile{Off, Browse, Video, Bulk} {
		t.Run(string(pr), func(t *testing.T) {
			var buf bytes.Buffer
			s := New(&buf, Config{Profile: pr})
			var want []byte
			chunk := make([]byte, proto.MaxPayload)
			for i := 0; i < 750; i++ { // ~1 МБ
				for j := range chunk {
					chunk[j] = byte(i*7 + j)
				}
				want = append(want, chunk...)
				if err := proto.WriteFrame(s, proto.Header{Type: proto.TypeData, Stream: 1}, chunk); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			got := dataOnly(t, buf.Bytes())
			if !bytes.Equal(got, want) {
				t.Fatalf("данные искажены: %d из %d байт", len(got), len(want))
			}
		})
	}
}

// dataOnly — payload не-PAD кадров из потока.
func dataOnly(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	for len(b) > 0 {
		if len(b) < headerLen {
			t.Fatalf("обрыв заголовка: %d байт", len(b))
		}
		n := headerLen + int(b[4])<<8 + int(b[5])
		if n > len(b) {
			t.Fatalf("длина кадра %d больше остатка %d", n, len(b))
		}
		if b[0] != proto.TypePad {
			out = append(out, b[headerLen:n]...)
		}
		b = b[n:]
	}
	return out
}

func TestUrgentBypass(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Voice})
	defer s.Close()
	if _, err := s.Write(dataFrame(80, 0)); err != nil { // каденция voice: следующая запись через 20 мс
		t.Fatal(err)
	}
	urg := dataFrame(200, proto.FlagUrgent)
	start := time.Now()
	if _, err := s.Write(urg); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > cadenceSlack {
		t.Fatalf("URGENT задержан на %v", d)
	}
	if last := snk.last(); last != len(urg) {
		t.Fatalf("URGENT записан %d байт вместо %d: паддинг недопустим", last, len(urg))
	}
}

func TestUrgentFlushesPending(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Browse})
	defer s.Close()
	small := dataFrame(100, 0)
	if _, err := s.Write(small); err != nil {
		t.Fatal(err)
	}
	urg := dataFrame(50, proto.FlagUrgent)
	if _, err := s.Write(urg); err != nil {
		t.Fatal(err)
	}
	if snk.count() != 1 || snk.last() != len(small)+len(urg) {
		t.Fatalf("URGENT не вытолкнул накопленное сразу: %d записей", snk.count())
	}
	if _, pad := stream(t, snk); pad != 0 {
		t.Fatalf("паддинг в URGENT-пути: %d", pad)
	}
}

func TestCoalesceByTimer(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Video}) // окно больше кадра: всегда ждём
	defer s.Close()
	if _, err := s.Write(dataFrame(100, 0)); err != nil {
		t.Fatal(err)
	}
	if snk.count() != 0 {
		t.Fatalf("мелкая запись ушла одиночной")
	}
	time.Sleep(10 * time.Millisecond)
	if snk.count() != 1 {
		t.Fatalf("накопленное не отправлено таймером")
	}
}

func TestCloseFlushes(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Browse})
	if _, err := s.Write(dataFrame(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if snk.count() != 1 {
		t.Fatalf("Close потерял накопленное")
	}
}

func TestVoiceCadence(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Voice})
	defer s.Close()
	const n = 21
	ts := make([]time.Time, n)
	for i := 0; i < n; i++ {
		if _, err := s.Write(dataFrame(200, 0)); err != nil {
			t.Fatal(err)
		}
		ts[i] = time.Now()
	}
	var sum time.Duration
	for i := 1; i < n; i++ {
		d := ts[i].Sub(ts[i-1]) - cadence
		if d < 0 {
			d = -d
		}
		sum += d
	}
	if mean := sum / (n - 1); mean > cadenceSlack {
		t.Fatalf("среднее отклонение каденции %v > %v", mean, cadenceSlack)
	}
}

func TestWriteAllocs(t *testing.T) {
	snk := &sink{quiet: true}
	s := New(snk, Config{Profile: Browse})
	defer s.Close()
	rec := dataFrame(proto.MaxPayload-8, 0) // 1400 Б — типичная запись mux
	for i := 0; i < 100; i++ {              // уходим за 64 КБ начала сессии
		s.Write(rec)
	}
	if n := testing.AllocsPerRun(1000, func() { s.Write(rec) }); n != 0 {
		t.Fatalf("аллокаций на запись: %v", n)
	}
}

// muxPair — две сессии TMN/1 через шейпер: проверяем, что форма трафика не ломает протокол.
func muxPair(t *testing.T, pr Profile) (*mux.Session, *mux.Session) {
	t.Helper()
	psk := bytes.Repeat([]byte{0x11}, 32)
	exp := bytes.Repeat([]byte{0x22}, 32)
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	errc := make(chan error, 1)
	var srv *mux.Session
	go func() {
		var err error
		srv, err = mux.New(New(s, Config{Profile: pr}), mux.Config{PSK: psk, Exporter: exp})
		errc <- err
	}()
	cli, err := mux.New(New(c, Config{Profile: pr}), mux.Config{IsClient: true, PSK: psk, Exporter: exp})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server New: %v", err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

func TestMuxThroughShaper(t *testing.T) {
	target := []byte{2, 3, 'a', 'b', 'c', 0, 80}
	tests := []struct {
		pr   Profile
		size int
	}{
		{Browse, 1 << 20}, {Video, 1 << 20}, {Bulk, 1 << 20}, {Voice, 128 << 10},
	}
	for _, tc := range tests {
		t.Run(string(tc.pr), func(t *testing.T) {
			cli, srv := muxPair(t, tc.pr)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			go func() {
				st, err := srv.AcceptStream(ctx)
				if err != nil {
					return
				}
				io.Copy(st, st)
				st.Close()
			}()
			st, err := cli.OpenStream(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			data := make([]byte, tc.size)
			for i := range data {
				data[i] = byte(i*31 + 7)
			}
			go func() {
				if _, err := st.Write(data); err != nil {
					t.Error(err)
				}
			}()
			got := make([]byte, tc.size)
			if _, err := io.ReadFull(st, got); err != nil {
				t.Fatalf("чтение: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("данные через mux+шейпер искажены")
			}
		})
	}
}
