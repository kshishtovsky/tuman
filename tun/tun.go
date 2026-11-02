// Package tun — L3-устройство для режима TUN: пакеты IP как есть, без
// userspace-стека. Соединение двух устройств (клиентское и серверное) целиком
// делают cmd/tmnc и cmd/tmns; здесь только платформенная часть и разбор
// заголовков.
package tun

import (
	"errors"
	"net/netip"
)

// MTU — размер IP-пакета на устройстве. 1398 = 1400 (максимальная нагрузка
// кадра mux) − 2 байта длины: пакет ложится в один кадр ровно, без второго
// почти пустого. 1398 влезает в путь с MTU 1500 с запасом под TLS-обёртку.
const MTU = 1398

// ErrUnsupported — платформа без TUN (сборка под что-то кроме linux/windows).
var ErrUnsupported = errors.New("tun: платформа не поддержана")

// Device — сетевой интерфейс уровня IP. Read блокируется до пакета и не
// возвращает пакеты длиннее MTU.
type Device interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	Name() string
}

// Addrs разбирает заголовок пакета: адреса и номер протокола (6 TCP, 17 UDP,
// 58 ICMPv6). ok=false — мусор, обрезанный пакет или не наш IP-версии.
func Addrs(p []byte) (src, dst netip.Addr, proto uint8, ok bool) {
	if len(p) < 1 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return
		}
		return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), p[9], true
	case 6:
		if len(p) < 40 {
			return
		}
		var s, d [16]byte
		copy(s[:], p[8:24])
		copy(d[:], p[24:40])
		return netip.AddrFrom16(s), netip.AddrFrom16(d), p[6], true
	}
	return
}

// PrefixOf — подсеть устройства из «10.66.0.1/24»: по ней обе стороны решают,
// кому адресован пакет.
func PrefixOf(s string) (netip.Prefix, error) {
	return netip.ParsePrefix(s)
}
