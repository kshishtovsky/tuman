package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/tuman/route"
)

// RFC 1928 / RFC 1929.
const (
	socksVer      = 5
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	mNoAuth       = 0x00
	mUserPass     = 0x02
	mNone         = 0xFF
	repOK         = 0x00
	repFailure    = 0x01
	repNoCommand  = 0x07 // BIND не поддержан
	repAddr       = 0x08
	repNotAllowed = 0x02 // запрещено правилом маршрутизации
	authVer       = 1
	// SOCKS5 ATYP не совпадает с нашим адресным блоком (там 2=domain, 3=IPv6).
	saIPv4      = 0x01
	saDomain    = 0x03
	saIPv6      = 0x04
	handshakeTO = 10 * time.Second // рукопожатие SOCKS и ожидание сессии при CONNECT
	// Предел одновременных CONNECT и простой в релее: без них брошенные сокеты
	// копятся пачками и держат окно туннеля.
	maxSocksConns = 512
	relayIdle     = 300 * time.Second
)

var (
	errSocks = errors.New("socks: отказ")
	errAtyp  = errors.New("socks: неизвестный atyp")
)

func (p *proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *proxy) handle(c net.Conn) {
	select {
	case p.sem <- struct{}{}: // лимит одновременных CONNECT
		defer func() { <-p.sem }()
	default:
		c.Close()
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTO))
	cmd, host, port, err := p.negotiate(c)
	if err != nil {
		p.log.Warn("SOCKS: рукопожатие отклонено", "reason", err.Error())
		// ответ уже отправлен: мягкое закрытие, иначе Windows рвёт RST и клиент теряет ответ
		closeWrite(c)
		io.Copy(io.Discard, c)
		return
	}
	c.SetDeadline(time.Time{})

	// UDP ASSOCIATE: дальше живём датаграммами, адрес в запросе — свой же
	// (RFC 1928 разрешает нули), поэтому маршрут решается на каждую цель.
	if cmd == cmdUDPAssoc {
		p.serveUDPAssociate(c)
		return
	}

	// Split-tunnel по цели: приложение SOCKS5 не знает, поэтому domain/CIDR/port.
	portNum, _ := strconv.Atoi(port)
	act := route.Tunnel
	if p.rt != nil { // nil = правил нет (proxy собран в тесте или routes_file пуст)
		act = p.rt.Decide(host, portNum)
	}
	if act != route.Tunnel {
		// сам хост не логируем: NFR-11 — никаких целей в логах
		p.log.Debug("SOCKS: маршрут", "action", act.String())
	}
	switch act {
	case route.Block:
		p.reply(c, repNotAllowed)
		return
	case route.Direct:
		p.direct(c, host, port)
		return
	}

	opened := time.Now()
	st, err := p.open(host, port)
	if err != nil {
		p.log.Warn("SOCKS: поток не открыт", "reason", err.Error(), "ms", time.Since(opened).Milliseconds())
		p.reply(c, repFailure)
		return
	}
	p.log.Debug("SOCKS: поток открыт", "ms", time.Since(opened).Milliseconds())
	if err := p.reply(c, repOK); err != nil {
		st.Close()
		return
	}
	p.relay(idleConn{c, relayIdle}, st)
}

// negotiate доводит рукопожатие до CONNECT и возвращает цель; отказы отвечает сам.
func (p *proxy) negotiate(c net.Conn) (cmd byte, host, port string, err error) {
	var b [2]byte
	if _, err = io.ReadFull(c, b[:]); err != nil {
		return
	}
	if b[0] != socksVer {
		return 0, "", "", fmt.Errorf("%w: ver=%#x", errSocks, b[0])
	}
	methods := make([]byte, b[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return
	}
	m := p.pickMethod(methods)
	if _, err = c.Write([]byte{socksVer, m}); err != nil {
		return
	}
	if m == mNone {
		return 0, "", "", fmt.Errorf("%w: нет общего метода", errSocks)
	}
	if m == mUserPass {
		if err = p.subAuth(c); err != nil {
			return
		}
	}

	var r [4]byte
	if _, err = io.ReadFull(c, r[:]); err != nil {
		return
	}
	if r[0] != socksVer {
		return 0, "", "", fmt.Errorf("%w: r0=%#x", errSocks, r[0])
	}
	if r[1] != cmdConnect && r[1] != cmdUDPAssoc {
		p.reply(c, repNoCommand)
		return 0, "", "", fmt.Errorf("%w: cmd=%#x", errSocks, r[1])
	}
	host, port, err = readAddr(c, r[3])
	if err != nil {
		rep := byte(repFailure)
		if errors.Is(err, errAtyp) {
			rep = repAddr
		}
		p.reply(c, rep)
		return 0, "", "", errSocks
	}
	return r[1], host, port, nil
}

// pickMethod: с паролем в конфиге метод 0x00 не принимается.
func (p *proxy) pickMethod(ms []byte) byte {
	want := byte(mNoAuth)
	if p.cfg.SocksAuth != "" {
		want = mUserPass
	}
	for _, m := range ms {
		if m == want {
			return want
		}
	}
	return mNone
}

func (p *proxy) subAuth(c net.Conn) error {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != authVer {
		return fmt.Errorf("%w: subauth ver=%#x", errSocks, h[0])
	}
	u := make([]byte, h[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return err
	}
	pw := make([]byte, pl[0])
	if _, err := io.ReadFull(c, pw); err != nil {
		return err
	}
	user, pass, _ := strings.Cut(p.cfg.SocksAuth, ":")
	ok := (subtle.ConstantTimeCompare(u, []byte(user)) & subtle.ConstantTimeCompare(pw, []byte(pass))) == 1
	res := byte(0)
	if !ok || pass == "" {
		res = 1
	}
	if _, err := c.Write([]byte{authVer, res}); err != nil {
		return err
	}
	if res != 0 {
		return fmt.Errorf("%w: subauth отклонён", errSocks)
	}
	return nil
}

func readAddr(c net.Conn, atyp byte) (host, port string, err error) {
	switch atyp {
	case saIPv4, saIPv6:
		n := net.IPv4len
		if atyp == saIPv6 {
			n = net.IPv6len
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(c, b); err != nil {
			return "", "", err
		}
		host = net.IP(b).String()
	case saDomain:
		var l [1]byte
		if _, err = io.ReadFull(c, l[:]); err != nil {
			return "", "", fmt.Errorf("readAddr: len: %w", err)
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(c, b); err != nil {
			return "", "", fmt.Errorf("readAddr: host: %w", err)
		}
		host = string(b)
	default:
		return "", "", errAtyp
	}
	var pb [2]byte
	if _, err = io.ReadFull(c, pb[:]); err != nil {
		return "", "", fmt.Errorf("readAddr: port: %w", err)
	}
	return host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))), nil
}

// reply: BND.ADDR нулевой — локальный адрес туннеля клиенту не нужен.
// replyAddr — успех с настоящим BND.ADDR (UDP ASSOCIATE): клиент обязан
// использовать именно этот адрес, а не «откуда пришёл ответ».
func (p *proxy) replyAddr(c net.Conn, a net.Addr) error {
	b := []byte{socksVer, repOK, 0, saIPv4, 0, 0, 0, 0, 0, 0}
	if ap, ok := a.(*net.UDPAddr); ok {
		ip := ap.IP.To4()
		if ip == nil {
			return p.reply(c, repFailure)
		}
		copy(b[4:], ip)
		binary.BigEndian.PutUint16(b[8:], uint16(ap.Port))
	}
	_, err := c.Write(b)
	return err
}

func (p *proxy) reply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{socksVer, rep, 0, saIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// open ждёт сессию не дольше handshakeTO: 30 с CONNECT висел дольше самого
// рукопожатия и клиент уже не понимал, жив ли прокси.
func (p *proxy) open(host, port string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTO)
	defer cancel()
	return p.con.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
}

// relay: FIN закрывает свою сторону, Reset освобождает поток у пира —
// иначе брошенный поток держит окно соединения и новые потоки встают.
func (p *proxy) relay(c net.Conn, st net.Conn) {
	var up, down atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, _ := io.Copy(st, c)
		up.Store(n)
		st.Close() // FIN: пиру больше нечего ждать от нас
	}()
	n, _ := io.Copy(c, st)
	down.Store(n)
	closeWrite(c)
	<-done
	if r, ok := st.(interface{ Reset() error }); ok {
		r.Reset() // пир перестаёт слать, окно соединения возвращается
	}
	p.log.Info("поток закрыт", "up", up.Load(), "down", down.Load())
}

// direct: мимо туннеля — обычный TCP, поток в mux не открывается.
// Dialer берём из конфига: у Android в его Control висит VpnService.protect,
// свой net.Dialer здесь уводил прямой поток мимо VPN (и петлёй обратно в туннель).
func (p *proxy) direct(c net.Conn, host, port string) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	up, err := p.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		p.log.Warn("SOCKS: прямой маршрут не открыт", "reason", reason(err))
		p.reply(c, repFailure)
		return
	}
	if err := p.reply(c, repOK); err != nil {
		up.Close()
		return
	}
	p.relayTCP(idleConn{c, relayIdle}, up)
}

// relayTCP — relay для прямого маршрута: пир не mux-поток, а обычное TCP.
func (p *proxy) relayTCP(c, up net.Conn) {
	var upN, downN atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, _ := io.Copy(up, c)
		upN.Store(n)
		closeWrite(up)
	}()
	n, _ := io.Copy(c, up)
	downN.Store(n)
	closeWrite(c)
	<-done
	up.Close()
	p.log.Info("прямой поток закрыт", "up", upN.Load(), "down", downN.Load())
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// idleConn держит дедлайн relayIdle на каждом Read/Write: брошенный SOCKS-сокет
// иначе висит вечно и держит поток в туннеле.
type idleConn struct {
	net.Conn
	d time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.d))
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.d))
	return c.Conn.Write(p)
}

func (c idleConn) CloseWrite() error { return closeWrite(c.Conn) }
