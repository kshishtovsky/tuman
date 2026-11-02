//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// Open создаёт (или переиспользует) устройство /dev/net/tun. Требует CAP_NET_ADMIN.
func Open(name string) (Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("tun: имя %q: %w", name, err)
	}
	// IFF_NO_PI: ядро не подмешивает 4-байтный префикс — иначе первый пакет
	// разбирается как мусор.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, ifr); err != nil {
		f.Close()
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", err)
	}
	return &dev{f: f, name: ifr.Name()}, nil
}

type dev struct {
	f    *os.File
	name string
}

func (d *dev) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *dev) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *dev) Close() error                { return d.f.Close() }
func (d *dev) Name() string                { return d.name }

// Configure — адрес, MTU и подъём интерфейса. Маршруты сознательно не трогаем:
// default через устройство ломает сам туннель, пока не прописан обходной путь
// до сервера (см. README).
func Configure(name string, addr netip.Prefix) error {
	for _, args := range [][]string{
		{"addr", "add", addr.String(), "dev", name},
		{"link", "set", "dev", name, "up", "mtu", fmt.Sprint(MTU)},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("tun: ip %v: %w: %s", args, err, out)
		}
	}
	return nil
}
