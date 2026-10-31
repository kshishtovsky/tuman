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
func records(t *testing.T, snk *sink) (pay, pad []int) {
	t.Helper()
	snk.mu.Lock()
	defer snk.mu.Unlock()
	b := snk.buf
	for i, size := range snk.sizes {
		if size > len(b) {
			t.Fatalf("запись %d: размер %d больше потока %d", i, size, len(b))
		}
		rec := b[:size]
		var p, d int
		for len(rec) > 0 {
			if len(rec) < headerLen {
				t.Fatalf("запись %d: обрыв заголовка (%d байт)", i, len(rec))
			}
			n := headerLen + int(rec[4])<<8 + int(rec[5])
			if n > len(rec) {
				t.Fatalf("запись %d: длина кадра %d больше записи %d", i, n, len(rec))
			}
			if rec[0] == proto.TypePad {
				d += int(rec[4])<<8 + int(rec[5])
			} else {
				p += int(rec[4])<<8 + int(rec[5])
			}
			rec = rec[n:]
		}
		pay, pad = append(pay, p), append(pad, d)
		b = b[size:]
	}
	return pay, pad
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

func TestBrowseSizes(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Browse})
	defer s.Close()
	for i := 0; i < 400; i++ { // 43 КБ полезной нагрузки — начало сессии
		if _, err := s.Write(dataFrame(100, 0)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	pay, pad := records(t, snk)
	for i := range pay {
		size := snk.sizes[i]
		if size > 1500 || (size < 700 && i < len(pay)-1) {
			// последняя запись может быть короче: потолок 2× нагрузки сильнее пола 700
			t.Fatalf("запись %d: размер %d вне [700,1500]", i, size)
		}
		if pad[i] > pay[i] { // ≤2× полезной нагрузки
			t.Fatalf("запись %d: паддинг %d больше полезной нагрузки %d", i, pad[i], pay[i])
		}
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
	pay, _ := records(t, snk)
	for i := range pay {
		if size := snk.sizes[i]; size < 1024 || size > 1400 {
			t.Fatalf("запись %d: размер %d вне [1024,1400]", i, size)
		}
	}
}

func TestBulkNoPadding(t *testing.T) {
	snk := &sink{}
	s := New(snk, Config{Profile: Bulk})
	defer s.Close()
	for i := 0; i < 200; i++ {
		if _, err := s.Write(dataFrame(300, 0)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	pay, pad := records(t, snk)
	for i := range pad {
		if pad[i] != 0 {
			t.Fatalf("bulk: паддинг %d байт в записи %d", pad[i], i)
		}
	}
	if len(pay) == 0 || pay[0] < 700 {
		t.Fatalf("bulk: первая запись %v, ждали коалесинг до ≥700", pay)
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
	s := New(snk, Config{Profile: Browse})
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
