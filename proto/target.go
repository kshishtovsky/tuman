package proto

// Адресный блок §3: atyp + адрес + port. Общий кодек для клиента и сервера.

import (
	"errors"
	"net"
	"strconv"
)

const (
	AtypIPv4   = 1
	AtypDomain = 2
	AtypIPv6   = 3
)

var ErrTarget = errors.New("proto: битый адрес цели")

// EncodeTarget кодирует host:port в адресный блок §3.
// host — IPv4, IPv6 (без скобок) или домен; port — число или строка с числом.
func EncodeTarget(host, port string) ([]byte, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, ErrTarget
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b := make([]byte, 0, 1+4+2)
			b = append(b, AtypIPv4)
			b = append(b, v4...)
			return append(b, byte(p>>8), byte(p)), nil
		}
		b := make([]byte, 0, 1+16+2)
		b = append(b, AtypIPv6)
		b = append(b, ip.To16()...)
		return append(b, byte(p>>8), byte(p)), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, ErrTarget
	}
	b := make([]byte, 0, 2+len(host)+2)
	b = append(b, AtypDomain, byte(len(host)))
	b = append(b, host...)
	return append(b, byte(p>>8), byte(p)), nil
}

// DecodeTarget разбирает адресный блок §3 в host и port.
func DecodeTarget(b []byte) (host, port string, err error) {
	if len(b) < 1 {
		return "", "", ErrTarget
	}
	var rest []byte
	switch b[0] {
	case AtypIPv4:
		if len(b) < 1+4+2 {
			return "", "", ErrTarget
		}
		host = net.IP(b[1 : 1+4]).String()
		rest = b[1+4:]
	case AtypIPv6:
		if len(b) < 1+16+2 {
			return "", "", ErrTarget
		}
		host = net.IP(b[1 : 1+16]).String()
		rest = b[1+16:]
	case AtypDomain:
		if len(b) < 2 {
			return "", "", ErrTarget
		}
		n := int(b[1])
		if n == 0 || len(b) < 2+n+2 {
			return "", "", ErrTarget
		}
		host = string(b[2 : 2+n])
		rest = b[2+n:]
	default:
		return "", "", ErrTarget
	}
	p := int(rest[0])<<8 | int(rest[1])
	if p == 0 {
		return "", "", ErrTarget
	}
	return host, strconv.Itoa(p), nil
}

// TargetLen возвращает длину адресного блока или -1, если он битый.
func TargetLen(b []byte) int {
	if _, _, err := DecodeTarget(b); err != nil {
		return -1
	}
	_, _, _ = DecodeTarget(b)
	// длина = весь блок; считаем по atyp
	switch b[0] {
	case AtypIPv4:
		return 1 + 4 + 2
	case AtypIPv6:
		return 1 + 16 + 2
	case AtypDomain:
		return 2 + int(b[1]) + 2
	}
	return -1
}
