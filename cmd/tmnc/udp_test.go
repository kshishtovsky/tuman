package main

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// UDP ASSOCIATE целиком: датаграмма с SOCKS-заголовком уходит в туннель,
// возвращается с адресом цели и тем же телом. Фейковый сервер (socks_test.go)
// релеит UDP тем же форматом кадров, что и cmd/tmns.
func TestSocksUDPRoundTrip(t *testing.T) {
	e := newEnv(t, "")
	pc := udpEcho(t)
	host, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	c, rep, bnd, err := socksUDPAssoc(e.socksAddr)
	if err != nil || rep != repOK {
		t.Fatalf("UDP ASSOCIATE: rep=%#x err=%v", rep, err)
	}
	defer c.Close()
	if bnd == nil || bnd.Port == 0 {
		t.Fatalf("BND.ADDR пустой: %v", bnd)
	}

	for _, payload := range []string{"dnspkt", strings.Repeat("z", 3000)} {
		hdr, err := udpHeader(host, port)
		if err != nil {
			t.Fatal(err)
		}
		msg := append(append([]byte{}, hdr...), payload...)
		if _, err := c.WriteTo(msg, bnd); err != nil {
			t.Fatalf("отправка: %v", err)
		}
		buf := make([]byte, 65536)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ответ (%d байт): %v", len(payload), err)
		}
		if !from.(*net.UDPAddr).IP.Equal(bnd.IP) {
			t.Fatalf("ответ от %v, ждали от %v", from, bnd)
		}
		rhost, rport, off, err := udpAddr(buf[:n])
		if err != nil {
			t.Fatalf("разбор ответа: %v", err)
		}
		if rhost != host || rport != port {
			t.Fatalf("адрес в ответе %s:%s, ждали %s:%s", rhost, rport, host, port)
		}
		if got := string(buf[off:n]); got != payload {
			t.Fatalf("эхо %d байт, получено %d", len(payload), len(got))
		}
	}
}

// Датаграммы чужого процесса не обслуживаются: ассоциация привязана к первому
// источнику, иначе локальный UDP-резолвер доступен любому на хосте.
func TestSocksUDPForeignSource(t *testing.T) {
	e := newEnv(t, "")
	pc := udpEcho(t)
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	owner, rep, bnd, err := socksUDPAssoc(e.socksAddr)
	if err != nil || rep != repOK {
		t.Fatalf("UDP ASSOCIATE: rep=%#x err=%v", rep, err)
	}
	defer owner.Close()
	hdr, _ := udpHeader(host, port)
	// первый источник фиксируется нами
	if _, err := owner.WriteTo(append(hdr, "mine"...), bnd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	owner.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := owner.ReadFrom(buf); err != nil {
		t.Fatalf("свой запрос не вернулся: %v", err)
	}

	alien, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer alien.Close()
	if _, err := alien.WriteTo(append(hdr, "alien"...), bnd); err != nil {
		t.Fatal(err)
	}
	alien.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if n, _, err := alien.ReadFrom(buf); err == nil {
		t.Fatalf("чужому источнику ответили %d байт", n)
	}
}

// Разбор заголовка: домен, IPv4, IPv6, битые длины.
func TestUDPAddrParse(t *testing.T) {
	dom, _ := udpHeader("example.com", "53")
	if h, p, off, err := udpAddr(append(dom, []byte("abc")...)); err != nil || h != "example.com" || p != "53" || off != len(dom) {
		t.Fatalf("домен: %s %s %d %v", h, p, off, err)
	}
	v6, err := udpHeader("2001:db8::1", "443")
	if err != nil {
		t.Fatal(err)
	}
	if h, p, _, err := udpAddr(append(v6, 1, 2)); err != nil || h != "2001:db8::1" || p != "443" {
		t.Fatalf("IPv6: %s %s %v", h, p, err)
	}
	for name, b := range map[string][]byte{
		"короткий":      {0, 0, 0},
		"чужой atyp":    {0, 0, 0, 0x09, 1, 2},
		"обрезанный":    {0, 0, 0, saDomain, 10, 'a'},
		"нулевой домен": {0, 0, 0, saDomain, 0, 0, 53},
	} {
		if _, _, _, err := udpAddr(b); err == nil {
			t.Fatalf("%s: принят", name)
		}
	}
}

// Фрагментированные датаграммы (FRAG≠0) отбрасываются, а не склеиваются.
func TestSocksUDPFragmentDropped(t *testing.T) {
	e := newEnv(t, "")
	pc := udpEcho(t)
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	c, rep, bnd, err := socksUDPAssoc(e.socksAddr)
	if err != nil || rep != repOK {
		t.Fatalf("UDP ASSOCIATE: rep=%#x err=%v", rep, err)
	}
	defer c.Close()
	hdr, _ := udpHeader(host, port)
	msg := append(hdr, "frag"...)
	msg[2] = 1 // FRAG: фрагмент номер 1
	if _, err := c.WriteTo(msg, bnd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if n, _, err := c.ReadFrom(buf); err == nil {
		t.Fatalf("фрагмент обслужен: %d байт", n)
	}
}

// socksUDPAssoc — CMD=0x03 с разбором BND.ADDR: адрес обязан быть настоящим,
// потому что клиент шлёт датаграммы именно туда.
func socksUDPAssoc(addr string) (net.PacketConn, byte, *net.UDPAddr, error) {
	tc, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, 0, nil, err
	}
	// Без defer: TCP-контроль обязан жить, пока живёт ассоциация — сервер
	// закрывает UDP-сокет вместе с ним (RFC 1928 §7).
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tc.Write([]byte{socksVer, 1, mNoAuth}); err != nil {
		return nil, 0, nil, err
	}
	var mr [2]byte
	if _, err := io.ReadFull(tc, mr[:]); err != nil {
		return nil, 0, nil, err
	}
	req := []byte{socksVer, cmdUDPAssoc, 0, saIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := tc.Write(req); err != nil {
		return nil, 0, nil, err
	}
	var rh [4]byte
	if _, err := io.ReadFull(tc, rh[:]); err != nil {
		return nil, 0, nil, err
	}
	if rh[1] != repOK {
		return nil, rh[1], nil, nil
	}
	var ip net.IP
	switch rh[3] {
	case saIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(tc, b); err != nil {
			return nil, rh[1], nil, err
		}
		ip = net.IP(b)
	case saIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(tc, b); err != nil {
			return nil, rh[1], nil, err
		}
		ip = net.IP(b)
	default:
		return nil, rh[1], nil, nil
	}
	var pb [2]byte
	if _, err := io.ReadFull(tc, pb[:]); err != nil {
		return nil, rh[1], nil, err
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tc.Close()
		return nil, rh[1], nil, err
	}
	tc.SetDeadline(time.Time{})
	return &assocConn{PacketConn: pc, ctl: tc, t: time.Now()}, rh[1],
		&net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(pb[:]))}, nil
}

// assocConn держит TCP-контроль открытым, пока жива UDP-«сессия» теста.
type assocConn struct {
	net.PacketConn
	ctl net.Conn
	t   time.Time
}

func (a *assocConn) Close() error {
	a.ctl.Close()
	return a.PacketConn.Close()
}

func udpEcho(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return pc
}

var _ = strconv.Itoa
