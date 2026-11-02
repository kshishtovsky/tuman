package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/route"
)

// UDP ASSOCIATE (RFC 1928 §7). Датаграммы идут в mux-потоке, помеченном
// FlagUDP: по одному потоку на цель, содержимое — u16 длина + полезная
// нагрузка. Целей у приложения немного (резолвер, QUIC к паре CDN), поэтому
// карта живёт на ассоциацию и умирает вместе с TCP-контролем.
const (
	udpAssocIdle = 120 * time.Second // молчание ассоциации
	udpDestIdle  = 60 * time.Second  // молчание одной цели
	maxUDPDest   = 64                // потолок целей на одну ассоциацию
	maxDatagram  = 8 << 10
)

// udpDest — одна цель ассоциации: поток туннеля либо прямой сокет
// (split-tunnel: route.Block/Direct обязаны работать и для UDP, иначе блокировка
// цели молча обходится датаграммами).
type udpDest struct {
	st   *mux.Stream
	pc   net.Conn
	last time.Time
	mu   sync.Mutex // запись из двух горутин: клиент и таймаут
}

func (d *udpDest) write(p []byte) error {
	if d.pc != nil {
		_, err := d.pc.Write(p)
		return err
	}
	return writeDatagram(d.st, p)
}

func (d *udpDest) read(buf []byte) (int, error) {
	if d.pc != nil {
		return d.pc.Read(buf)
	}
	return readDatagram(d.st, buf)
}

func (d *udpDest) deadline(t time.Time) {
	if d.pc != nil {
		d.pc.SetDeadline(t)
		return
	}
	d.st.SetReadDeadline(t)
}

func (d *udpDest) Close() {
	if d.pc != nil {
		d.pc.Close()
		return
	}
	d.st.Close()
}

type udpAssoc struct {
	p     *proxy
	conn  net.PacketConn
	peer  net.Addr // адрес клиента, чьи датаграммы принимаем
	relay string   // адрес, который мы объявили клиенту (BND)

	mu    sync.Mutex
	dests map[string]*udpDest
}

// serveUDPAssociate — ответ на CMD=0x03. Живёт, пока жив TCP-контроль.
func (p *proxy) serveUDPAssociate(c net.Conn) {
	// BND.ADDR клиент не использует: он шлёт датаграммы туда, откуда пришёл
	// ответ, но по RFC обязан уважать присланный адрес — отдаём реальный.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		p.reply(c, repFailure)
		return
	}
	defer pc.Close()

	a := &udpAssoc{p: p, conn: pc, relay: pc.LocalAddr().String(), dests: map[string]*udpDest{}}
	if err := p.replyAddr(c, pc.LocalAddr()); err != nil {
		return
	}
	p.log.Debug("SOCKS: UDP-ассоциация")

	go func() { // конец ассоциации — смерть TCP-контроля
		io.Copy(io.Discard, c)
		pc.Close()
	}()
	a.loop()
}

func (a *udpAssoc) loop() {
	buf := make([]byte, maxDatagram)
	for {
		a.conn.SetReadDeadline(time.Now().Add(udpAssocIdle))
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			break
		}
		// Первый источник фиксируется: иначе любой процесс на хосте получит
		// наш резолвер и egress-канал в подарок.
		a.mu.Lock()
		switch {
		case a.peer == nil:
			a.peer = from
		case from.String() != a.peer.String():
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()
		if n < 4 {
			continue
		}
		// RSV(2) FRAG(1): фрагментация не поддержана — по RFC такие датаграммы
		// отбрасываются, а не склеиваются на глаз.
		if buf[2] != 0 {
			continue
		}
		host, port, off, err := udpAddr(buf[:n])
		if err != nil {
			continue
		}
		d := a.dest(host, port)
		if d == nil {
			continue
		}
		d.mu.Lock()
		werr := d.write(buf[off:n])
		d.mu.Unlock()

		if werr != nil {
			a.drop(host, port)
		}
	}
	a.mu.Lock()
	for _, d := range a.dests {
		d.Close()
	}
	a.dests = nil
	a.mu.Unlock()
}

// dest отдаёт канал к цели, открывая его при первом обращении.
func (a *udpAssoc) dest(host, port string) *udpDest {
	key := net.JoinHostPort(host, port)
	a.mu.Lock()
	if d, ok := a.dests[key]; ok {
		if a.dests == nil {
			a.mu.Unlock()
			return nil
		}
		d.last = time.Now()
		a.mu.Unlock()
		return d
	}
	full := len(a.dests) >= maxUDPDest
	a.mu.Unlock()
	if full {
		return nil
	}

	pn, _ := strconv.Atoi(port)
	act := route.Tunnel
	if a.p.rt != nil {
		act = a.p.rt.Decide(host, pn)
	}
	if act == route.Block { // молча: цель не должна узнать, что её спросили
		a.p.log.Debug("SOCKS: UDP отброшен маршрутом")
		return nil
	}

	d := &udpDest{last: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if act == route.Direct {
		pc, err := a.p.dialer.DialContext(ctx, "udp", key)
		if err != nil {
			a.p.log.Debug("SOCKS: прямой UDP не открыт", "reason", reason(err))
			return nil
		}
		d.pc = pc
	} else {
		st, err := a.p.con.OpenUDP(ctx, host, port)
		if err != nil {
			a.p.log.Debug("SOCKS: UDP-поток не открыт", "reason", err.Error())
			return nil
		}
		d.st = st
	}

	a.mu.Lock()
	if a.dests == nil { // ассоциация закрыта, пока открывали
		a.mu.Unlock()
		d.Close()
		return nil
	}
	a.dests[key] = d
	a.mu.Unlock()
	go a.readBack(host, port, d)
	return d
}

// readBack — ответы цели уходят клиенту с SOCKS-заголовком его адреса.
func (a *udpAssoc) readBack(host, port string, d *udpDest) {
	defer a.drop(host, port)
	buf := make([]byte, maxDatagram)
	hdr, err := udpHeader(host, port)
	if err != nil {
		return
	}
	out := make([]byte, 0, len(hdr)+maxDatagram)
	for {
		d.deadline(time.Now().Add(udpDestIdle))
		n, err := d.read(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		peer := a.peer
		a.mu.Unlock()
		if peer == nil {
			continue
		}
		out = append(append(out[:0], hdr...), buf[:n]...)
		a.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.conn.WriteTo(out, peer); err != nil {
			return
		}
	}
}

func (a *udpAssoc) drop(host, port string) {
	key := net.JoinHostPort(host, port)
	a.mu.Lock()
	d, ok := a.dests[key]
	delete(a.dests, key)
	a.mu.Unlock()
	if ok {
		d.Close()
	}
}

// writeDatagram/readDatagram — кадр внутри потока: u16 длина + данные.
// Границу держит mux: поток фрагментируется на DATA-кадры по 1400 байт.
func writeDatagram(st *mux.Stream, p []byte) error {
	if len(p) > maxDatagram { // сервер такой кадр сочтёт нарушением формата
		return errors.New("socks: датаграмма сверх потолка")
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(p)))
	if _, err := st.Write(h[:]); err != nil {
		return err
	}
	_, err := st.Write(p)
	return err
}

func readDatagram(st *mux.Stream, buf []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(st, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 0 || n > len(buf) {
		return 0, errors.New("socks: датаграмма не по размеру")
	}
	_, err := io.ReadFull(st, buf[:n])
	return n, err
}

// udpAddr разбирает SOCKS5 UDP-заголовок и отдаёт смещение данных.
// Раскладка: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func udpAddr(b []byte) (host, port string, off int, err error) {
	if len(b) < 4 {
		return "", "", 0, errAtyp
	}
	switch b[3] {
	case saIPv4:
		if len(b) < 4+4+2 {
			return "", "", 0, errAtyp
		}
		host, off = net.IP(b[4:8]).String(), 4+4
	case saIPv6:
		if len(b) < 4+16+2 {
			return "", "", 0, errAtyp
		}
		host, off = net.IP(b[4:20]).String(), 4+16
	case saDomain:
		if len(b) < 5 {
			return "", "", 0, errAtyp
		}
		n := int(b[4])
		if n == 0 || len(b) < 5+n+2 {
			return "", "", 0, errAtyp
		}
		host, off = string(b[5:5+n]), 5+n
	default:
		return "", "", 0, errAtyp
	}
	return host, strconv.Itoa(int(binary.BigEndian.Uint16(b[off:]))), off + 2, nil
}

// udpHeader — тот же заголовок для ответа клиенту.
func udpHeader(host, port string) ([]byte, error) {
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return nil, errAtyp
	}
	b := []byte{0, 0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b[3] = saIPv4
			b = append(b, v4...)
		} else {
			b[3] = saIPv6
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errAtyp
		}
		b[3] = saDomain
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}
	return append(b, byte(pn>>8), byte(pn)), nil
}
