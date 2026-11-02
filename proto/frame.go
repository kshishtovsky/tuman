// Package proto — кадрирование и AUTH TMN/1 (docs/07-proto-v1-spec.md, §2 и §4).
package proto

import (
	"encoding/binary"
	"errors"
	"io"
)

// Типы кадров (§2).
const (
	TypeData   = 0x01
	TypeAck    = 0x02
	TypePad    = 0x03
	TypePing   = 0x04
	TypeWU     = 0x05
	TypeFin    = 0x06
	TypeMig    = 0x07
	TypeAuth   = 0x08
	TypeAuthOK = 0x09
	TypeClose  = 0x0A
)

// Флаги кадра (§2).
const (
	FlagOpen   = 0x01
	FlagFin    = 0x02
	FlagMore   = 0x04
	FlagUrgent = 0x08
	// FlagUDP на OPEN: поток несёт датаграммы, а не поток байт. Старый сервер
	// неизвестный бит игнорирует и попробует TCP — UDP на нём не работает,
	// поэтому клиент и сервер обновляются вместе.
	FlagUDP = 0x10
	// FlagIP на OPEN: поток несёт IP-пакеты (режим TUN). Адресного блока у
	// такого потока нет, цель выбирает стек вызывающей стороны.
	FlagIP = 0x20
)

const (
	MaxPayload = 1400
	headerLen  = 8
	maxStream  = 0x7FFF
)

var (
	ErrShortFrame = errors.New("proto: кадр короче заголовка")
	ErrLength     = errors.New("proto: length > 1400")
	ErrType       = errors.New("proto: неизвестный тип")
	ErrStream     = errors.New("proto: stream вне [0, 0x7FFF]")
	ErrBufSmall   = errors.New("proto: буфер меньше 8+1400")
)

type Header struct {
	Type, Flags uint8
	Stream      uint16
	Length      uint16
}

// MarshalTo пишет 8 байт заголовка; b должен быть >= 8.
func (h Header) MarshalTo(b []byte) {
	b = b[:headerLen]
	b[0] = h.Type
	b[1] = h.Flags
	binary.BigEndian.PutUint16(b[2:], h.Stream)
	binary.BigEndian.PutUint16(b[4:], h.Length)
	binary.BigEndian.PutUint16(b[6:], 0) // reserved
}

// ParseHeader валидирует заголовок по §2; неизвестные биты flags не ошибка.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < headerLen {
		return Header{}, ErrShortFrame
	}
	h := Header{
		Type:   b[0],
		Flags:  b[1],
		Stream: binary.BigEndian.Uint16(b[2:]),
		Length: binary.BigEndian.Uint16(b[4:]),
	}
	if h.Length > MaxPayload {
		return Header{}, ErrLength
	}
	if int(h.Stream) > maxStream {
		return Header{}, ErrStream
	}
	if !knownType(h.Type) {
		return Header{}, ErrType
	}
	return h, nil
}

func knownType(t uint8) bool { return t >= TypeData && t <= TypeClose }

// ReadFrame читает кадр в buf (>= 8+MaxPayload); payload — срез buf, без аллокаций.
func ReadFrame(r io.Reader, buf []byte) (Header, []byte, error) {
	if len(buf) < headerLen+MaxPayload {
		return Header{}, nil, ErrBufSmall
	}
	if _, err := io.ReadFull(r, buf[:headerLen]); err != nil {
		return Header{}, nil, err
	}
	h, err := ParseHeader(buf[:headerLen])
	if err != nil {
		return Header{}, nil, err
	}
	p := buf[headerLen : headerLen+int(h.Length)]
	if _, err := io.ReadFull(r, p); err != nil {
		return Header{}, nil, err
	}
	return h, p, nil
}

// WriteFrame пишет кадр; Length всегда равен len(payload).
func WriteFrame(w io.Writer, h Header, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrLength
	}
	h.Length = uint16(len(payload))
	var hb [headerLen]byte
	h.MarshalTo(hb[:])
	if _, err := w.Write(hb[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// WUPayload кодирует WU: stream u16 + delta u32.
func WUPayload(stream uint16, delta uint32) [6]byte {
	var b [6]byte
	binary.BigEndian.PutUint16(b[0:], stream)
	binary.BigEndian.PutUint32(b[2:], delta)
	return b
}

func ParseWU(p []byte) (stream uint16, delta uint32, ok bool) {
	if len(p) != 6 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(p[0:]), binary.BigEndian.Uint32(p[2:]), true
}
