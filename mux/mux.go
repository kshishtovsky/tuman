// Package mux — мультиплексирование потоков TMN/1: один writer-goroutine на
// батчинг кадров, один reader-goroutine на диспетчеризацию по stream.
package mux

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"tuman/proto"
)

const (
	winStream = 4 << 20
	winConn   = 16 << 20
	batchSize = 64 << 10
	batchWait = time.Millisecond
	pingEvery = 25 * time.Second
	pingMiss  = 3
	acceptCap = 256
	outCap    = 512
	hsTimeout = 10 * time.Second

	reasonProtocol = 0x01
	reasonClosed   = 0x02
)

var (
	ErrClosed      = errors.New("mux: сессия закрыта")
	ErrStream      = errors.New("mux: поток закрыт")
	ErrProtocol    = errors.New("mux: нарушение протокола")
	ErrHandshake   = errors.New("mux: handshake не удался")
	ErrPingTimeout = errors.New("mux: нет ответа на PING")
	ErrTarget      = errors.New("mux: битый адрес цели")
	ErrAcceptFull  = errors.New("mux: очередь accept переполнена")
)

// Буферы фиксированных классов; в пул кладём указатели, чтобы Put не аллоцировал.
type frameBuf [8 + proto.MaxPayload]byte
type chunkBuf [4096]byte
type batchBuf [batchSize]byte

var (
	pFrame = sync.Pool{New: func() any { return new(frameBuf) }}
	pChunk = sync.Pool{New: func() any { return new(chunkBuf) }}
	pBatch = sync.Pool{New: func() any { return new(batchBuf) }}
)

// frame — готовый кадр (заголовок + payload) в буфере из пула.
type frame struct {
	buf *frameBuf
	n   int
}

type Config struct {
	IsClient   bool
	PSK        []byte // 32 байта
	Exporter   []byte // 32 байта из TLS
	WindowConn uint32 // 0 => 16 MiB
}

type Session struct {
	conn io.ReadWriter
	cfg  Config
	max  int // максимальный payload пира

	mu       sync.Mutex
	streams  map[uint16]*Stream
	connWin  int32
	connWait chan struct{}
	connUsed int32
	nextID   uint16

	out     chan frame
	accept  chan *Stream
	done    chan struct{}
	writerD chan struct{}

	closeOnce sync.Once
	err       error

	replay   *proto.ReplayCache
	lastRecv atomic.Int64

	pingMu    sync.Mutex
	pingNonce [8]byte
}

func New(conn io.ReadWriter, cfg Config) (*Session, error) {
	if len(cfg.PSK) != 32 || len(cfg.Exporter) != 32 {
		return nil, ErrHandshake
	}
	wc := int32(winConn)
	if cfg.WindowConn != 0 {
		wc = int32(cfg.WindowConn)
	}
	s := &Session{
		conn:     conn,
		cfg:      cfg,
		max:      proto.MaxPayload,
		streams:  make(map[uint16]*Stream),
		connWin:  wc,
		connWait: make(chan struct{}),
		out:      make(chan frame, outCap),
		accept:   make(chan *Stream, acceptCap),
		done:     make(chan struct{}),
		writerD:  make(chan struct{}),
	}
	if cfg.IsClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	if err := s.handshake(); err != nil {
		return nil, err
	}
	go s.writeLoop()
	go s.readLoop()
	go s.keepalive()
	return s, nil
}

func (s *Session) handshake() error {
	type deadliner interface{ SetDeadline(time.Time) error }
	if d, ok := s.conn.(deadliner); ok {
		d.SetDeadline(time.Now().Add(hsTimeout))
		defer d.SetDeadline(time.Time{})
	}
	if s.cfg.IsClient {
		return s.authClient()
	}
	return s.authServer()
}

func (s *Session) authClient() error {
	p, err := proto.MakeAuth(s.cfg.PSK, s.cfg.Exporter, time.Now())
	if err != nil {
		return err
	}
	if err := proto.WriteFrame(s.conn, proto.Header{Type: proto.TypeAuth}, p); err != nil {
		return err
	}
	var buf [8 + proto.MaxPayload]byte
	h, rp, err := proto.ReadFrame(s.conn, buf[:])
	if err != nil {
		return err
	}
	if h.Type != proto.TypeAuthOK {
		return ErrHandshake
	}
	mp, wc, _, err := proto.ParseAuthOK(rp)
	if err != nil {
		return ErrHandshake
	}
	if mp > 0 && int(mp) < s.max {
		s.max = int(mp)
	}
	if wc > 0 {
		s.connWin = int32(wc)
	}
	return nil
}

func (s *Session) authServer() error {
	var buf [8 + proto.MaxPayload]byte
	h, p, err := proto.ReadFrame(s.conn, buf[:])
	if err != nil {
		return err
	}
	// Не-AUTH кадр — это HTTP-зонд: сайт-прикрытие живёт выше mux (§4).
	if h.Type != proto.TypeAuth {
		return ErrHandshake
	}
	now := time.Now()
	if err := proto.VerifyAuth(s.cfg.PSK, s.cfg.Exporter, p, now); err != nil {
		return err
	}
	ts, nonce, ok := proto.AuthPayloadTS(p)
	if !ok {
		return ErrHandshake
	}
	if s.replay == nil {
		s.replay = proto.NewReplayCache()
	}
	if s.replay.Seen(now, ts, nonce) {
		return proto.ErrAuth
	}
	okp := proto.MakeAuthOK(proto.MaxPayload, uint32(s.connWin), proto.CapUrgent)
	return proto.WriteFrame(s.conn, proto.Header{Type: proto.TypeAuthOK}, okp)
}

func (s *Session) Done() <-chan struct{} { return s.done }

// Close мягко：шлёт CLOSE, даёт writer'у сбросить батч и закрывает соединение.
func (s *Session) Close() error {
	s.fail(ErrClosed, reasonClosed)
	t := time.NewTimer(2 * time.Second)
	defer t.Stop()
	select {
	case <-s.writerD:
	case <-t.C:
		if c, ok := s.conn.(io.Closer); ok {
			c.Close()
		}
		<-s.writerD
	}
	return nil
}

func (s *Session) OpenStream(ctx context.Context, target []byte) (*Stream, error) {
	if n := targetLen(target); n < 0 || n != len(target) {
		return nil, ErrTarget
	}
	s.mu.Lock()
	if s.isClosed() {
		s.mu.Unlock()
		return nil, s.closedErr()
	}
	id := s.nextID
	if id == 0 || id > 0x7FFF {
		s.mu.Unlock()
		return nil, ErrStream
	}
	s.nextID += 2
	s.mu.Unlock()

	st := s.newStream(id, append([]byte(nil), target...))
	if !s.register(st) {
		return nil, ErrStream
	}
	h := proto.Header{Type: proto.TypeData, Flags: proto.FlagOpen, Stream: id}
	if _, err := st.write(ctx, h, target); err != nil {
		s.drop(st)
		return nil, err
	}
	return st, nil
}

func (s *Session) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.closedErr()
	}
}

func (s *Session) newStream(id uint16, target []byte) *Stream {
	return &Stream{
		s:       s,
		id:      id,
		tgt:     target,
		sendWin: winStream,
		rwake:   make(chan struct{}, 1),
		wait:    make(chan struct{}),
	}
}

func (s *Session) register(st *Stream) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams[st.id] != nil {
		return false
	}
	s.streams[st.id] = st
	return true
}

func (s *Session) drop(st *Stream) {
	s.mu.Lock()
	if s.streams[st.id] == st {
		delete(s.streams, st.id)
	}
	s.mu.Unlock()
}

func (s *Session) stream(id uint16) *Stream {
	s.mu.Lock()
	st := s.streams[id]
	s.mu.Unlock()
	return st
}

func (s *Session) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// closedErr — ошибка закрытия; s.err читается только после получения из done.
func (s *Session) closedErr() error {
	select {
	case <-s.done:
		if s.err != nil {
			return s.err
		}
		return ErrClosed
	default:
		return ErrClosed
	}
}

func (s *Session) fail(err error, reason byte) {
	s.closeOnce.Do(func() {
		s.err = err
		if f, e := s.build(proto.Header{Type: proto.TypeClose}, []byte{reason}); e == nil {
			select {
			case s.out <- f:
			default:
				pFrame.Put(f.buf)
			}
		}
		close(s.done)
	})
}

func (s *Session) build(h proto.Header, p []byte) (frame, error) {
	if len(p) > proto.MaxPayload {
		return frame{}, proto.ErrLength
	}
	fb := pFrame.Get().(*frameBuf)
	h.Length = uint16(len(p))
	h.MarshalTo(fb[:])
	copy(fb[8:], p)
	return frame{buf: fb, n: 8 + len(p)}, nil
}

func (s *Session) send(h proto.Header, p []byte) error {
	f, err := s.build(h, p)
	if err != nil {
		return err
	}
	select {
	case s.out <- f:
		return nil
	case <-s.done:
		pFrame.Put(f.buf)
		return s.closedErr()
	}
}

func (s *Session) onWU(id uint16, delta uint32) {
	s.mu.Lock()
	if id == 0 {
		s.connWin += int32(delta)
		close(s.connWait)
		s.connWait = make(chan struct{})
	} else if st := s.streams[id]; st != nil {
		st.sendWin += int32(delta)
		close(st.wait)
		st.wait = make(chan struct{})
	}
	s.mu.Unlock()
}

func (s *Session) readLoop() {
	buf := make([]byte, 8+proto.MaxPayload)
	for {
		h, p, err := proto.ReadFrame(s.conn, buf)
		if err != nil {
			if err == io.EOF {
				err = ErrClosed
			}
			s.fail(err, reasonClosed)
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		if err := s.handle(h, p); err != nil {
			s.fail(err, reasonProtocol)
			return
		}
	}
}

func (s *Session) handle(h proto.Header, p []byte) error {
	switch h.Type {
	case proto.TypeData:
		return s.onData(h, p)
	case proto.TypeFin:
		if st := s.stream(h.Stream); st != nil {
			st.remoteFin()
		}
		return nil
	case proto.TypeWU:
		id, delta, ok := proto.ParseWU(p)
		if !ok {
			return ErrProtocol
		}
		s.onWU(id, delta)
		return nil
	case proto.TypePing:
		if len(p) != 8 {
			return ErrProtocol
		}
		s.onPing(p)
		return nil
	case proto.TypeClose:
		s.fail(ErrClosed, reasonClosed)
		return nil
	default:
		// PAD, MIG, ACK, AUTH/AUTH_OK после handshake — игнор
		return nil
	}
}

func (s *Session) onPing(p []byte) {
	s.pingMu.Lock()
	ours := bytes.Equal(p, s.pingNonce[:])
	s.pingMu.Unlock()
	if ours {
		return
	}
	s.send(proto.Header{Type: proto.TypePing}, p)
}

func (s *Session) onData(h proto.Header, p []byte) error {
	if h.Stream == 0 {
		return ErrProtocol
	}
	fin := h.Flags&proto.FlagFin != 0
	if h.Flags&proto.FlagOpen != 0 {
		if (h.Stream%2 == 0) != s.cfg.IsClient {
			return ErrProtocol // чужая чётность (§3)
		}
		n := targetLen(p)
		if n < 0 {
			return ErrProtocol
		}
		st := s.newStream(h.Stream, append([]byte(nil), p[:n]...))
		if !s.register(st) {
			return ErrProtocol // OPEN на уже открытом
		}
		select {
		case s.accept <- st:
		default:
			s.drop(st)
			return ErrAcceptFull
		}
		return st.deliver(p[n:], fin)
	}
	st := s.stream(h.Stream)
	if st == nil {
		return ErrProtocol // DATA на неоткрытом
	}
	return st.deliver(p, fin)
}

func (s *Session) writeLoop() {
	defer close(s.writerD)
	bp := pBatch.Get().(*batchBuf)
	batch := bp[:0]
	t := time.NewTimer(time.Hour)
	t.Stop()
	var tc <-chan time.Time

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if _, err := s.conn.Write(batch); err != nil {
			s.fail(err, reasonClosed)
			return err
		}
		batch = batch[:0]
		return nil
	}
	push := func(f frame) error {
		if len(batch)+f.n > cap(batch) {
			if err := flush(); err != nil {
				pFrame.Put(f.buf)
				return err
			}
		}
		batch = append(batch, f.buf[:f.n]...)
		pFrame.Put(f.buf)
		return nil
	}
	stopTimer := func() {
		if tc != nil {
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			tc = nil
		}
	}

loop:
	for {
		select {
		case f := <-s.out:
			urgent := f.buf[1]&proto.FlagUrgent != 0
			if push(f) != nil {
				break loop
			}
			if urgent || len(batch) >= batchSize {
				stopTimer()
				if flush() != nil {
					break loop
				}
				continue
			}
			if tc == nil {
				t.Reset(batchWait)
				tc = t.C
			}
		case <-tc:
			tc = nil
			if flush() != nil {
				break loop
			}
		case <-s.done:
			for {
				select {
				case f := <-s.out:
					if push(f) != nil {
						break loop
					}
				default:
					flush()
					break loop
				}
			}
		}
	}
	stopTimer()
	pBatch.Put(bp)
	// соединение закрывает только writer: reader разблокируется на ошибке чтения
	if c, ok := s.conn.(io.Closer); ok {
		c.Close()
	}
}

func (s *Session) keepalive() {
	t := time.NewTimer(pingEvery)
	defer t.Stop()
	prev := s.lastRecv.Load()
	misses := 0
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		cur := s.lastRecv.Load()
		if cur == prev {
			misses++
			if misses >= pingMiss {
				s.fail(ErrPingTimeout, reasonProtocol)
				return
			}
			s.ping()
		} else {
			misses = 0
		}
		prev = cur
		t.Reset(pingEvery)
	}
}

func (s *Session) ping() {
	var n [8]byte
	rand.Read(n[:])
	s.pingMu.Lock()
	s.pingNonce = n
	s.pingMu.Unlock()
	s.send(proto.Header{Type: proto.TypePing}, n[:])
}

// targetLen — длина адресного блока §3 (atyp+addr+port) или -1.
func targetLen(b []byte) int {
	if len(b) < 1 {
		return -1
	}
	switch b[0] {
	case 1: // IPv4
		if len(b) >= 7 {
			return 7
		}
	case 2: // domain
		if len(b) >= 2 && len(b) >= 2+int(b[1])+2 {
			return 2 + int(b[1]) + 2
		}
	case 3: // IPv6
		if len(b) >= 19 {
			return 19
		}
	}
	return -1
}
