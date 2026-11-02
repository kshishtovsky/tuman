package main

import (
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

// Пакет из устройства доходит до сервера и возвращается в устройство — через
// настоящий mux по TLS, а не в обход транспорта.
func TestTunModeRoundTrip(t *testing.T) {
	e := newEnv(t, "")
	dev := newFakeDev()
	tm := &tunMode{dev: dev, pkts: make(chan []byte, 8)}
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
