package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"tuman/mux"
	"tuman/proto"
)

// RFC 1928 / RFC 1929.
const (
	socksVer     = 5
	cmdConnect   = 0x01
	mNoAuth      = 0x00
	mUserPass    = 0x02
	mNone        = 0xFF
	repOK        = 0x00
	repFailure   = 0x01
	repNoCommand = 0x07 // BIND и UDP ASSOCIATE в MVP не поддержаны
	repAddr      = 0x08
	authVer      = 1
	handshakeTO  = 10 * time.Second
	openTimeout  = 30 * time.Second // ожидание сессии при CONNECT (переподключение с backoff)
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
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTO))
	host, port, err := p.negotiate(c)
	if err != nil {
		p.log.Warn("SOCKS: рукопожатие отклонено", "reason", err.Error())
		// ответ уже отправлен: мягкое закрытие, иначе Windows рвёт RST и клиент теряет ответ
		closeWrite(c)
		io.Copy(io.Discard, c)
		return
	}
	c.SetDeadline(time.Time{})

	target, err := proto.EncodeTarget(host, port)
	if err != nil {
		p.reply(c, repAddr)
		return
	}
	st, err := p.open(target)
	if err != nil {
		p.log.Warn("SOCKS: поток не открыт", "reason", err.Error())
		p.reply(c, repFailure)
		return
	}
	if err := p.reply(c, repOK); err != nil {
		st.Close()
		return
	}
	p.relay(c, st)
}

// negotiate доводит рукопожатие до CONNECT и возвращает цель; отказы отвечает сам.
func (p *proxy) negotiate(c net.Conn) (host, port string, err error) {
	var b [2]byte
	if _, err = io.ReadFull(c, b[:]); err != nil {
		return
	}
	if b[0] != socksVer {
		return "", "", errSocks
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
		return "", "", errSocks
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
		return "", "", errSocks
	}
	if r[1] != cmdConnect {
		p.reply(c, repNoCommand)
		return "", "", errSocks
	}
	host, port, err = readAddr(c, r[3])
	if err != nil {
		rep := byte(repFailure)
		if errors.Is(err, errAtyp) {
			rep = repAddr
		}
		p.reply(c, rep)
		return "", "", errSocks
	}
	return host, port, nil
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
		return errSocks
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
		return errSocks
	}
	return nil
}

func readAddr(c net.Conn, atyp byte) (host, port string, err error) {
	switch atyp {
	case proto.AtypIPv4, proto.AtypIPv6:
		n := net.IPv4len
		if atyp == proto.AtypIPv6 {
			n = net.IPv6len
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(c, b); err != nil {
			return "", "", err
		}
		host = net.IP(b).String()
	case proto.AtypDomain:
		var l [1]byte
		if _, err = io.ReadFull(c, l[:]); err != nil {
			return "", "", err
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(c, b); err != nil {
			return "", "", err
		}
		host = string(b)
	default:
		return "", "", errAtyp
	}
	var pb [2]byte
	if _, err = io.ReadFull(c, pb[:]); err != nil {
		return "", "", err
	}
	return host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))), nil
}

// reply: BND.ADDR нулевой — локальный адрес туннеля клиенту не нужен.
func (p *proxy) reply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{socksVer, rep, 0, proto.AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// open ждёт сессию не дольше openTimeout: иначе CONNECT висит, пока сервер недоступен.
func (p *proxy) open(target []byte) (*mux.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	return p.con.open(ctx, target)
}

// relay: FIN закрывает только поток (§3 спеки), сессия живёт.
func (p *proxy) relay(c net.Conn, st *mux.Stream) {
	var up, down atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, _ := io.Copy(st, c)
		up.Store(n)
		st.Close()
	}()
	n, _ := io.Copy(c, st)
	down.Store(n)
	closeWrite(c)
	<-done
	p.log.Info("поток закрыт", "up", up.Load(), "down", down.Load())
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
