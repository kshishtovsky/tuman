package proto

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

var ErrTarget = errors.New("proto: битый адрес цели")

// TargetLen — длина адресного блока §3 (atyp || addr || port) или -1.
func TargetLen(b []byte) int {
	if len(b) < 1 {
		return -1
	}
	switch b[0] {
	case 1: // IPv4
		if len(b) >= 7 {
			return 7
		}
	case 2: // domain
		if len(b) >= 2 && b[1] > 0 && len(b) >= 2+int(b[1])+2 {
			return 2 + int(b[1]) + 2
		}
	case 3: // IPv6
		if len(b) >= 19 {
			return 19
		}
	}
	return -1
}

// EncodeTarget кодирует "host:port" (host — литерал IP или домен) в адресный блок §3.
func EncodeTarget(hostport string) ([]byte, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, ErrTarget
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		return nil, ErrTarget
	}
	var b []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			b = append([]byte{1}, ip.AsSlice()...)
		} else {
			b = append([]byte{3}, ip.AsSlice()...)
		}
	} else if len(host) > 0 && len(host) <= 255 {
		b = append([]byte{2, byte(len(host))}, host...)
	} else {
		return nil, ErrTarget
	}
	return append(b, byte(p>>8), byte(p)), nil
}

// DecodeTarget разбирает адресный блок §3 в "host:port" для net.Dial.
// Хвост после блока (первые данные потока) игнорируется.
func DecodeTarget(b []byte) (string, error) {
	n := TargetLen(b)
	if n < 0 || n > len(b) {
		return "", ErrTarget
	}
	var host string
	var p uint16
	switch b[0] {
	case 1:
		a, _ := netip.AddrFromSlice(b[1:5])
		host, p = a.String(), binary.BigEndian.Uint16(b[5:7])
	case 2:
		l := 2 + int(b[1])
		host, p = string(b[2:l]), binary.BigEndian.Uint16(b[l:l+2])
	case 3:
		a, _ := netip.AddrFromSlice(b[1:17])
		host, p = a.String(), binary.BigEndian.Uint16(b[17:19])
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p))), nil
}
