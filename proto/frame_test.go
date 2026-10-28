package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		h    Header
		pay  []byte
	}{
		{"empty", Header{Type: TypeData, Flags: FlagOpen, Stream: 1}, nil},
		{"small", Header{Type: TypeData, Flags: FlagOpen | FlagFin, Stream: 3}, []byte("abc")},
		{"max", Header{Type: TypeData, Stream: 0x7FFF}, bytes.Repeat([]byte{0xAB}, MaxPayload)},
		{"auth", Header{Type: TypeAuth}, bytes.Repeat([]byte{1}, authLen)},
		{"wu", Header{Type: TypeWU}, []byte{0, 1, 0, 0, 0, 2}},
	}
	buf := make([]byte, headerLen+MaxPayload)
	var w bytes.Buffer
	for _, c := range cases {
		w.Reset()
		if err := WriteFrame(&w, c.h, c.pay); err != nil {
			t.Fatalf("%s: WriteFrame: %v", c.name, err)
		}
		if w.Len() != headerLen+len(c.pay) {
			t.Fatalf("%s: записано %d байт, ждали %d", c.name, w.Len(), headerLen+len(c.pay))
		}
		h, p, err := ReadFrame(&w, buf)
		if err != nil {
			t.Fatalf("%s: ReadFrame: %v", c.name, err)
		}
		if h.Type != c.h.Type || h.Flags != c.h.Flags || h.Stream != c.h.Stream {
			t.Fatalf("%s: заголовок %+v, ждали %+v", c.name, h, c.h)
		}
		if h.Length != uint16(len(c.pay)) {
			t.Fatalf("%s: length %d, ждали %d", c.name, h.Length, len(c.pay))
		}
		if !bytes.Equal(p, c.pay) {
			t.Fatalf("%s: payload %q, ждали %q", c.name, p, c.pay)
		}
	}
}

func TestParseHeaderLengthBounds(t *testing.T) {
	h := Header{Type: TypeData, Stream: 1, Length: 0}
	b := make([]byte, headerLen)
	h.MarshalTo(b)
	if _, err := ParseHeader(b); err != nil {
		t.Fatalf("length=0: %v", err)
	}

	h.Length = MaxPayload
	h.MarshalTo(b)
	if _, err := ParseHeader(b); err != nil {
		t.Fatalf("length=1400: %v", err)
	}

	h.Length = MaxPayload + 1
	h.MarshalTo(b)
	if _, err := ParseHeader(b); err != ErrLength {
		t.Fatalf("length=1401: %v, ждали ErrLength", err)
	}

	if err := WriteFrame(&bytes.Buffer{}, Header{Type: TypeData}, make([]byte, MaxPayload+1)); err != ErrLength {
		t.Fatalf("WriteFrame 1401: %v, ждали ErrLength", err)
	}
}

func TestParseHeaderUnknownType(t *testing.T) {
	var b [headerLen]byte
	Header{Type: 0x0B, Stream: 1}.MarshalTo(b[:])
	if _, err := ParseHeader(b[:]); err != ErrType {
		t.Fatalf("тип 0x0B: %v, ждали ErrType", err)
	}
	Header{Type: 0x00, Stream: 1}.MarshalTo(b[:])
	if _, err := ParseHeader(b[:]); err != ErrType {
		t.Fatalf("тип 0x00: %v, ждали ErrType", err)
	}
}

func TestParseHeaderStreamRange(t *testing.T) {
	var b [headerLen]byte
	Header{Type: TypeData, Stream: 0x7FFF}.MarshalTo(b[:])
	if _, err := ParseHeader(b[:]); err != nil {
		t.Fatalf("stream=0x7FFF: %v", err)
	}
	Header{Type: TypeData, Stream: 0x8000}.MarshalTo(b[:])
	if _, err := ParseHeader(b[:]); err != ErrStream {
		t.Fatalf("stream=0x8000: %v, ждали ErrStream", err)
	}
}

// Неизвестные биты flags — forward compat, не ошибка.
func TestParseHeaderUnknownFlags(t *testing.T) {
	var b [headerLen]byte
	h := Header{Type: TypeData, Flags: FlagOpen | 0xF0, Stream: 1, Length: 2}
	h.MarshalTo(b[:])
	got, err := ParseHeader(b[:])
	if err != nil {
		t.Fatalf("flags 0xF1: %v", err)
	}
	if got.Flags != FlagOpen|0xF0 {
		t.Fatalf("flags %#x, ждали %#x", got.Flags, FlagOpen|0xF0)
	}
}

func TestParseHeaderShort(t *testing.T) {
	if _, err := ParseHeader(make([]byte, headerLen-1)); err != ErrShortFrame {
		t.Fatalf("7 байт: %v, ждали ErrShortFrame", err)
	}
	if _, _, err := ReadFrame(bytes.NewReader(nil), make([]byte, headerLen)); err != ErrBufSmall {
		t.Fatalf("маленький buf: %v, ждали ErrBufSmall", err)
	}
}

func TestReservedIgnored(t *testing.T) {
	var b [headerLen]byte
	Header{Type: TypePad, Stream: 2}.MarshalTo(b[:])
	binary.BigEndian.PutUint16(b[6:], 0xDEAD)
	if _, err := ParseHeader(b[:]); err != nil {
		t.Fatalf("reserved!=0: %v", err)
	}
}

func TestWUPayload(t *testing.T) {
	b := WUPayload(0x1234, 0xDEADBEEF)
	s, d, ok := ParseWU(b[:])
	if !ok || s != 0x1234 || d != 0xDEADBEEF {
		t.Fatalf("ParseWU(%x) = %#x, %#x, %v", b, s, d, ok)
	}
	if _, _, ok := ParseWU(b[:5]); ok {
		t.Fatal("ParseWU принял 5 байт")
	}
}

// DoD: 0 allocs/op.
func BenchmarkFrameRoundtrip(b *testing.B) {
	x := make([]byte, headerLen+MaxPayload)
	pay := bytes.Repeat([]byte{0x5A}, MaxPayload)
	var w bytes.Buffer
	w.Grow(4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := Header{Type: TypeData, Flags: FlagOpen, Stream: 3, Length: MaxPayload}
		h.MarshalTo(x[:headerLen])
		w.Write(x[:headerLen])
		w.Write(pay)
		rh, rp, err := ReadFrame(&w, x)
		if err != nil {
			b.Fatal(err)
		}
		if rh.Stream != 3 || len(rp) != MaxPayload {
			b.Fatal("битый кадр")
		}
	}
}

func BenchmarkMarshalHeader(b *testing.B) {
	var x [headerLen]byte
	h := Header{Type: TypeData, Flags: FlagOpen, Stream: 9, Length: 1400}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Stream = uint16(i)
		h.MarshalTo(x[:])
		sink = x[3]
	}
}

var sink byte
