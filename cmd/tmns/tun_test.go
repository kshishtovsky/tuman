package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/kshishtovsky/tuman/tun"
)

// Серверный батч — копия клиентского (пакеты main не делят), поэтому проверяем
// свою копию отдельно: формат «u16 длина + пакет» и сброс одной записью.
func TestServerTunBatchFraming(t *testing.T) {
	var b tunBatch
	b.buf = make([]byte, 0, batchMax*(2+tun.MTU))
	want := [][]byte{
		{0x45, 0, 0, 20},
		bytes.Repeat([]byte{0x11}, tun.MTU),
	}
	for _, p := range want {
		if !b.Fill(p) {
			t.Fatalf("Fill отверг пакет %d байт", len(p))
		}
	}
	if b.Fill(make([]byte, tun.MTU+1)) {
		t.Fatal("пакет больше MTU принят")
	}

	var out bytes.Buffer
	writes := 0
	w := writerFunc(func(p []byte) (int, error) { writes++; return out.Write(p) })
	if err := b.Flush(w); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("%d записей вместо одной", writes)
	}

	// Приёмная сторона: «2+len в цикле», как в toDevice.
	r := &out
	var got [][]byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("половина заголовка: %v", err)
		}
		p := make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, err := io.ReadFull(r, p); err != nil {
			t.Fatalf("кадр без тела: %v", err)
		}
		got = append(got, p)
	}
	if len(got) != len(want) {
		t.Fatalf("разобралось %d кадров вместо %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("кадр %d не совпал", i)
		}
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
