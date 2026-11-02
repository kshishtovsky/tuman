package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/tun"
)

// fakeDev — L3-устройство в памяти: то, что записали, читается обратно.
type fakeDev struct{ ch chan []byte }

func newFakeDev() *fakeDev { return &fakeDev{ch: make(chan []byte, 8)} }

func (d *fakeDev) Read(p []byte) (int, error) {
	b, ok := <-d.ch
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}
func (d *fakeDev) Write(p []byte) (int, error) {
	d.ch <- append([]byte(nil), p...)
	return len(p), nil
}
func (d *fakeDev) Close() error { close(d.ch); return nil }
func (d *fakeDev) Name() string { return "fake0" }

// echoIPStream — серверная половина теста: каждый кадр возвращается обратно.
func echoIPStream(st *mux.Stream) {
	buf := make([]byte, tun.MTU)
	for {
		var h [2]byte
		if _, err := io.ReadFull(st, h[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n == 0 || n > len(buf) {
			return
		}
		if _, err := io.ReadFull(st, buf[:n]); err != nil {
			return
		}
		var wh [2]byte
		binary.BigEndian.PutUint16(wh[:], uint16(n))
		if _, err := st.Write(wh[:]); err != nil {
			return
		}
		if _, err := st.Write(buf[:n]); err != nil {
			return
		}
	}
}

// benchDev — устройство, готовое отдать пакет сразу: кольцо и драйвер из замера
// выкинуты, меряется только путь «устройство → канал → поток».
type benchDev struct{ pkt []byte }

func (d *benchDev) Read(p []byte) (int, error)  { return copy(p, d.pkt), nil }
func (d *benchDev) Write(p []byte) (int, error) { return len(p), nil }
func (d *benchDev) Close() error                { return nil }
func (d *benchDev) Name() string                { return "bench0" }

// BenchmarkTunReadLoop — путь «устройство → пул → канал → батч» без mux:
// меряет аллокации на пакет. До пула было 1 allocs/op (make на каждый пакет).
func BenchmarkTunReadLoop(b *testing.B) {
	tm := &tunMode{dev: &benchDev{pkt: make([]byte, tun.MTU)}, pkts: make(chan *[]byte, 256)}
	go tm.readDevice()
	batch := tunBatch{buf: make([]byte, 0, batchMax*(2+tun.MTU))}
	b.ReportAllocs()
	b.SetBytes(tun.MTU)
	for i := 0; i < b.N; i++ {
		bp := <-tm.pkts
		batch.Fill(*bp)
		*bp = (*bp)[:cap(*bp)]
		pktPool.Put(bp)
		if batch.Full() {
			batch.Flush(io.Discard)
		}
	}
	batch.Flush(io.Discard)
}

// countBuf — bytes.Buffer, считающий Write: батч обязан писать одной записью.
type countBuf struct {
	bytes.Buffer
	writes int
}

func (c *countBuf) Write(p []byte) (int, error) { c.writes++; return c.Buffer.Write(p) }

// pkt — пакет длины n с меткой i во всех байтах: порядок кадров видно при разборе.
func pkt(i, n int) []byte {
	p := make([]byte, n)
	for j := range p {
		p[j] = byte(i)
	}
	return p
}

// parseFrames — приёмная сторона как в toDevice: читает «2+len» из потока
// байтов, не зная, сколько кадров пришло в одной записи.
func parseFrames(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var got [][]byte
	r := bytes.NewReader(b)
	for {
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err == io.EOF {
			return got
		} else if err != nil {
			t.Fatalf("батч кончился на половине длины: %v", err)
		}
		p := make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, err := io.ReadFull(r, p); err != nil {
			t.Fatalf("кадр без тела: %v", err)
		}
		got = append(got, p)
	}
}

// Три пакета уезжают одной записью, получатель разбирает их по «2+len» как
// отдельные кадры; девять — две записи (8 + 1), формат тот же.
func TestTunBatchFraming(t *testing.T) {
	var out countBuf
	var b tunBatch
	b.buf = make([]byte, 0, batchMax*(2+tun.MTU))

	want := [][]byte{pkt(1, 200), pkt(2, 200), pkt(3, 200)}
	for _, p := range want {
		if !b.Fill(p) {
			t.Fatal("Fill отверг пакет 200 Б")
		}
	}
	if err := b.Flush(&out); err != nil {
		t.Fatal(err)
	}
	if out.writes != 1 {
		t.Fatalf("%d записей вместо одной", out.writes)
	}
	got := parseFrames(t, out.Bytes())
	if len(got) != len(want) {
		t.Fatalf("разобралось %d кадров вместо %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("кадр %d не совпал", i)
		}
	}

	out.Reset()
	out.writes = 0
	var w9 [][]byte
	for i := 0; i < batchMax+1; i++ {
		p := pkt(i, 200)
		w9 = append(w9, p)
		b.Fill(p)
		if b.Full() {
			if err := b.Flush(&out); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := b.Flush(&out); err != nil {
		t.Fatal(err)
	}
	if out.writes != 2 {
		t.Fatalf("%d записей вместо 8+1", out.writes)
	}
	got = parseFrames(t, out.Bytes())
	if len(got) != len(w9) {
		t.Fatalf("разобралось %d кадров вместо %d", len(got), len(w9))
	}
	for i := range w9 {
		if !bytes.Equal(got[i], w9[i]) {
			t.Fatalf("кадр %d не совпал", i)
		}
	}
}

// Пакет больше MTU отбрасывается и не портит уже накопленное.
func TestTunBatchRejectsOversize(t *testing.T) {
	var b tunBatch
	b.buf = make([]byte, 0, batchMax*(2+tun.MTU))
	first, last := pkt(1, 100), pkt(2, 100)
	if !b.Fill(first) || !b.Fill(pkt(3, tun.MTU)) {
		t.Fatal("Fill отверг пакет в пределах MTU")
	}
	if b.Fill(make([]byte, tun.MTU+1)) {
		t.Fatal("пакет больше MTU принят")
	}
	if !b.Fill(last) {
		t.Fatal("Fill отказал после отбраковки")
	}
	var out countBuf
	if err := b.Flush(&out); err != nil {
		t.Fatal(err)
	}
	got := parseFrames(t, out.Bytes())
	if len(got) != 3 || !bytes.Equal(got[0], first) || !bytes.Equal(got[2], last) {
		t.Fatalf("батч испорчен: %d кадров", len(got))
	}
}

// Полный батч (8 пакетов MTU) уходит одной записью в 11.2 КиБ: mux режет её на
// MaxPayload, а сервер разбирает как отдельные кадры — формат на проводе цел.
func TestTunModeBatchedFrames(t *testing.T) {
	e := newEnv(t, "")
	dev := newFakeDev()
	tm := &tunMode{dev: dev, pkts: make(chan *[]byte, batchMax*2)}
	// Пакеты в канале до старта toStream: он видит непустой канал и копит их.
	for i := 0; i < batchMax; i++ {
		b := make([]byte, tun.MTU) // MTU, а не меньше: пул отдаёт буферы только такого размера
		b[0] = byte(i)
		bp := &b
		tm.pkts <- bp
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tm.run(ctx, e.p.con)

	for i := 0; i < batchMax; i++ {
		select {
		case got := <-dev.ch:
			if len(got) != tun.MTU || got[0] != byte(i) {
				t.Fatalf("пакет %d вернулся как %d байт с меткой %d", i, len(got), got[0])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("пакет %d не вернулся", i)
		}
	}
}

// Пакет из устройства доходит до сервера и возвращается в устройство — через
// настоящий mux по TLS, а не в обход транспорта.
func TestTunModeRoundTrip(t *testing.T) {
	e := newEnv(t, "")
	dev := newFakeDev()
	tm := &tunMode{dev: dev, pkts: make(chan *[]byte, 8)}
	go tm.readDevice()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tm.run(ctx, e.p.con)
	t.Cleanup(func() { dev.Close() })

	// Пакет-мусор: мост не разбирает IP, ему важна только длина.
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 66, 0, 2, 10, 66, 0, 99}
	for i := 0; i < 3; i++ {
		if _, err := dev.Write(pkt); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-dev.ch:
			if len(got) != len(pkt) {
				t.Fatalf("вернулось %d байт вместо %d", len(got), len(pkt))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("пакет %d не вернулся", i)
		}
	}
}
