//go:build windows

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// ringCapacity — размер общего кольца wintun. Как в wireguard-go: 4 МиБ хватает
// на гигабит с запасом, меньше — доставка начинает ждать.
const ringCapacity = 0x400000

// Open создаёт адаптер Wintun (нужен wintun.dll рядом с exe или в System32) и
// запускает сессию. Требует прав администратора.
func Open(name string) (Device, error) {
	a, err := wintun.CreateAdapter(name, "Tuman", nil)
	if err != nil {
		return nil, fmt.Errorf("tun: CreateAdapter: %w", err)
	}
	s, err := a.StartSession(ringCapacity)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("tun: StartSession: %w", err)
	}
	return &dev{a: a, s: &s, name: name}, nil
}

type dev struct {
	a      *wintun.Adapter
	s      *wintun.Session
	name   string
	closed atomic.Bool
}

func (d *dev) Read(p []byte) (int, error) {
	for {
		if d.closed.Load() {
			return 0, net.ErrClosed
		}
		pkt, err := d.s.ReceivePacket()
		if err == nil {
			n := copy(p, pkt)
			d.s.ReleaseReceivePacket(pkt)
			return n, nil
		}
		if err != windows.ERROR_NO_MORE_ITEMS {
			return 0, err
		}
		// Ждём пакет с таймаутом, чтобы Close не подвешивал читателя навсегда.
		windows.WaitForSingleObject(d.s.ReadWaitEvent(), 200)
	}
}

func (d *dev) Write(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > MTU {
		return 0, fmt.Errorf("tun: пакет %d байт больше MTU", len(p))
	}
	for {
		pkt, err := d.s.AllocateSendPacket(len(p))
		if err == nil {
			copy(pkt, p)
			d.s.SendPacket(pkt)
			return len(p), nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW { // ERROR_BUFFER_OVERFLOW — кольцо полно
			return 0, err
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (d *dev) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	d.s.End()
	return d.a.Close()
}

func (d *dev) Name() string { return d.name }

// Configure — адрес и MTU. Адаптер появляется в системе не мгновенно, поэтому
// netsh повторяется; маршруты не трогаем (см. README: обходной путь до сервера
// нужен раньше default через устройство).
func Configure(name string, addr netip.Prefix) error {
	ip := addr.Addr().String()
	mask := net.IP(net.CIDRMask(addr.Bits(), 32)).String()
	var err error
	for i := 0; i < 10; i++ {
		if err = exec.Command("netsh", "interface", "ipv4", "set", "address",
			"name="+name, "source=static", "address="+ip, "mask="+mask).Run(); err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("tun: netsh адрес: %w", err)
	}
	if out, err := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		name, fmt.Sprint("mtu=", MTU), "store=persistent").CombinedOutput(); err != nil {
		return fmt.Errorf("tun: netsh mtu: %w: %s", err, out)
	}
	return nil
}
