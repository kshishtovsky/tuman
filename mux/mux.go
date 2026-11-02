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

	"github.com/kshishtovsky/tuman/proto"
)

const (
	winStream = 8 << 20
	winConn   = 32 << 20
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
	// ErrExhausted — id кончились: сессию надо переоткрыть, потоков больше не будет.
	ErrExhausted = errors.New("mux: исчерпано пространство stream id")
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
	// PingEvery/PingMiss задают детект мёртвой сессии: молчание дольше
	// PingEvery*PingMiss закрывает сессию. 0 => 25s/3 (75 s). Мобильному
	// клиенту нужен туже: Doze усыпляет радио, NAT забывает поток, и
	// «живая» сессия иначе висит чёрной ещё минуту после пробуждения.
	PingEvery time.Duration
	PingMiss  int
	// AuthV2 — клиент просит AUTH v2 (X25519 + MAC сервера в AUTH_OK).
	// Сервер принимает обе версии всегда и различает их по длине кадра,
	// поэтому флаг нужен только клиенту: v1-клиенты продолжают работать.
	AuthV2 bool
	// Replay — общий на процесс кэш (ts, nonce). Без него сервер заводит
	// свой на сессию, что бесполезно: AUTH в сессии бывает один раз.
	Replay *proto.ReplayCache
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

	recvWin   int32 // наше окно приёма: сколько пир вправе держать у нас в полёте
	recvTotal int32 // доставлено и ещё не прочитано приложением по всем потокам

	out     chan frame
	accept  chan *Stream
	done    chan struct{}
	writerD chan struct{}

	closeOnce sync.Once
	err       error

	replay   *proto.ReplayCache
	lastRecv atomic.Int64

	// key/hasKey — сессионный ключ AUTH v2; у v1-сессий hasKey=false.
	key    [32]byte
	hasKey bool

	pingMu    sync.Mutex
	pingNonce [8]byte

	pingEvery time.Duration // детект мёртвой сессии (cfg.PingEvery)
	pingMiss  int           // сколько PING подряд без ответа терпим
}

// keepalive resolves the session-death detector: explicit values win, zero
// means the package defaults (25 s x 3).
func (c Config) keepalive() (time.Duration, int) {
	every, miss := pingEvery, pingMiss
	if c.PingEvery > 0 {
		every = c.PingEvery
	}
	if c.PingMiss > 0 {
		miss = c.PingMiss
	}
	return every, miss
}

func New(conn io.ReadWriter, cfg Config) (*Session, error) {
	// exporter нужен только AUTH v1: v2 привязывается к X25519, а uTLS вообще
	// не отдаёт ExportKeyingMaterial, поэтому браузерный отпечаток ходит с nil.
	if len(cfg.PSK) != 32 || (!cfg.AuthV2 && len(cfg.Exporter) != 32) {
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
		recvWin:  wc,
		connWait: make(chan struct{}),
		out:      make(chan frame, outCap),
		accept:   make(chan *Stream, acceptCap),
		done:     make(chan struct{}),
		writerD:  make(chan struct{}),
	}
	s.pingEvery, s.pingMiss = cfg.keepalive()
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
	if s.cfg.AuthV2 {
		return s.authClientV2()
	}
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

// authClientV2 — AUTH v2: X25519-пара, MAC сервера в AUTH_OK. Клиент обязан
// проверить тег до первого целевого байта: иначе MITM с доверенным сертификатом
// выдаёт себя за сервер и видит цели.
func (s *Session) authClientV2() error {
	priv, err := proto.NewEphemeralKeyV2()
	if err != nil {
		return ErrHandshake
	}
	pub := proto.PublicKeyV2(priv)
	p, err := proto.MakeAuthV2(s.cfg.PSK, pub, time.Now())
	if err != nil {
		return ErrHandshake
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
	// ts и nonce берём из своей же AUTH: сервер обязан их отразить.
	ts, nonce, _, err := proto.VerifyAuthV2(s.cfg.PSK, p, time.Now())
	if err != nil {
		return ErrHandshake
	}
	if err := proto.VerifyAuthOKV2(s.cfg.PSK, rp, pub, nonce, ts); err != nil {
		return ErrHandshake // сервер не доказал знание PSK
	}
	key, err := proto.SessionKeyV2(s.cfg.PSK, priv, rp[10:42])
	if err != nil {
		return ErrHandshake
	}
	s.key, s.hasKey = key, true
	// Лимиты пира — из AUTH_OK v2 (12-байтового разбора у v2 нет).
	if len(rp) >= proto.AuthOKV2Len {
		return nil
	}
	return ErrHandshake
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
	// Версию различаем по длине кадра: у v2 она фиксированная и не совпадает
	// с v1, поэтому отдельное согласование не нужно и старый клиент работает.
	if len(p) == proto.AuthV2Len {
		return s.authServerV2(p)
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

// authServerV2 — серверная половина AUTH v2. Проверяет MAC клиента, реплей по
// общему на процесс кэшу и отвечает AUTH_OK с собственным MAC: с этого момента
// клиент точно знает, что говорит с владельцем PSK.
func (s *Session) authServerV2(p []byte) error {
	now := time.Now()
	ts, nonce, cliPub, err := proto.VerifyAuthV2(s.cfg.PSK, p, now)
	if err != nil {
		return err
	}
	rc := s.cfg.Replay
	if rc == nil {
		rc = proto.NewReplayCache()
	}
	if rc.Seen(now, ts, nonce) {
		return proto.ErrAuth // тот же (ts, nonce) уже был: реплей
	}
	priv, err := proto.NewEphemeralKeyV2()
	if err != nil {
		return ErrHandshake
	}
	srvPub := proto.PublicKeyV2(priv)
	okp, err := proto.MakeAuthOKV2(s.cfg.PSK, cliPub, srvPub, nonce, ts)
	if err != nil {
		return ErrHandshake
	}
	if err := proto.WriteFrame(s.conn, proto.Header{Type: proto.TypeAuthOK}, okp); err != nil {
		return err
	}
	key, err := proto.SessionKeyV2(s.cfg.PSK, priv, cliPub)
	if err != nil {
		return ErrHandshake
	}
	s.key, s.hasKey = key, true
	return nil
}

// Key — сессионный ключ AUTH v2 (32 байта). ok=false для v1-сессий: там ключа нет.
func (s *Session) Key() (key [32]byte, ok bool) { return s.key, s.hasKey }

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
		// Без io.Closer writer может висеть в conn.Write вечно: не ждём его
		// дольше, но и не даём Close() висеть самому.
		select {
		case <-s.writerD:
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

func (s *Session) OpenStream(ctx context.Context, target []byte) (*Stream, error) {
	return s.OpenStreamKind(ctx, target, false)
}

// OpenStreamKind открывает поток; udp помечает его как датаграммный (SOCKS5 UDP
// ASSOCIATE), сервер по этой пометке релеит UDP вместо TCP.
func (s *Session) OpenStreamKind(ctx context.Context, target []byte, udp bool) (*Stream, error) {
	flags := uint8(proto.FlagOpen)
	if udp {
		flags |= proto.FlagUDP
	}
	return s.open(ctx, target, flags)
}

// OpenTun открывает поток IP-пакетов (режим TUN): адресного блока у него нет,
// поэтому цель в OPEN не передаётся вовсе.
func (s *Session) OpenTun(ctx context.Context) (*Stream, error) {
	return s.open(ctx, nil, proto.FlagOpen|proto.FlagIP)
}

func (s *Session) open(ctx context.Context, target []byte, flags uint8) (*Stream, error) {
	if flags&proto.FlagIP == 0 {
		if n := proto.TargetLen(target); n < 0 || n != len(target) {
			return nil, ErrTarget
		}
	}
	s.mu.Lock()
	if s.isClosed() {
		s.mu.Unlock()
		return nil, s.closedErr()
	}
	id := s.nextID
	if id == 0 || id > 0x7FFF {
		s.mu.Unlock()
		return nil, ErrExhausted
	}
	s.nextID += 2
	s.mu.Unlock()

	st := s.newStream(id, append([]byte(nil), target...))
	st.udp = flags&proto.FlagUDP != 0
	st.ip = flags&proto.FlagIP != 0
	if !s.register(st) {
		return nil, ErrStream
	}
	h := proto.Header{Type: proto.TypeData, Flags: flags, Stream: id}
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

// onStreamClose — пир сбросил поток (CLOSE с id != 0): освобождаем его и
// возвращаем окно соединения за недочитанные байты, иначе окно утекает и
// новые потоки встают навсегда.
func (s *Session) onStreamClose(id uint16, p []byte) error {
	st := s.stream(id)
	if st == nil {
		return nil // поток уже закрыт — CLOSE мог прийти на гонке
	}
	st.resetLocal(ErrStream)
	s.returnRecvWindow(st)
	return nil
}

// returnRecvWindow возвращает пиру кредит за доставленные, но не прочитанные
// байты потока: при закрытии они уже не будут прочитаны, а окно соединения
// останется занятым навсегда.
func (s *Session) returnRecvWindow(st *Stream) {
	s.mu.Lock()
	pend := st.recvPending
	st.recvPending = 0
	if s.recvTotal -= pend; s.recvTotal < 0 {
		s.recvTotal = 0
	}
	s.mu.Unlock()
	if pend > 0 {
		// Асинхронно: читающий goroutine НЕ должен блокироваться на отправке,
		// иначе забитая очередь исходящих вешает приём целиком (дедлок:
		// writer ждёт conn.Write, reader ждёт очередь).
		go func() {
			wu := proto.WUPayload(0, uint32(pend))
			s.send(proto.Header{Type: proto.TypeWU}, wu[:])
		}()
	}
}

// killStream рвёт один поток, не роняя сессию: окно за недочитанное пиру
// возвращаем, CLOSE шлём неблокирующе.
func (s *Session) killStream(st *Stream, reason byte) {
	s.returnRecvWindow(st)
	st.resetLocal(ErrProtocol)
	s.trySend(proto.Header{Type: proto.TypeClose, Stream: st.id}, []byte{reason})
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

// trySend — неблокирующая отправка: false, если очередь исходящих полна.
func (s *Session) trySend(h proto.Header, p []byte) bool {
	f, err := s.build(h, p)
	if err != nil {
		return true // некорректный кадр отбрасываем, очередь не занимаем
	}
	select {
	case s.out <- f:
		return true
	default:
		pFrame.Put(f.buf)
		return false
	}
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

// onWU начисляет кредит, но не больше номинала окна: delta близка к 2^32
// иначе уводит окно в минус (Write виснет навсегда) или раздувает его выше
// буфера пира.
func (s *Session) onWU(id uint16, delta uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == 0 {
		if delta == 0 || delta > winConn {
			return
		}
		s.connWin = int32(min(int64(s.connWin)+int64(delta), int64(winConn)))
		close(s.connWait)
		s.connWait = make(chan struct{})
		return
	}
	st := s.streams[id]
	if st == nil || delta == 0 || delta > winStream {
		return
	}
	st.sendWin = int32(min(int64(st.sendWin)+int64(delta), int64(winStream)))
	close(st.wait)
	st.wait = make(chan struct{})
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
		if h.Stream != 0 {
			return s.onStreamClose(h.Stream, p)
		}
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
		n := 0
		if h.Flags&proto.FlagIP == 0 { // у потока IP-пакетов адресного блока нет
			if n = proto.TargetLen(p); n < 0 || n != len(p) {
				return ErrProtocol
			}
		}
		st := s.newStream(h.Stream, append([]byte(nil), p[:n]...))
		st.udp = h.Flags&proto.FlagUDP != 0
		st.ip = h.Flags&proto.FlagIP != 0
		if !s.register(st) {
			// Дубль OPEN: рвём только этот id, сессию не трогаем.
			if old := s.stream(h.Stream); old != nil {
				s.killStream(old, reasonProtocol)
			}
			return nil
		}
		select {
		case s.accept <- st:
		default:
			// Очередь accept полна: отказываем одному потоку, а не всей
			// сессии — иначе 400 OPEN рвут все живые туннели.
			s.killStream(st, reasonProtocol)
			return nil
		}
		if err := st.deliver(p[n:], fin); err != nil {
			if err == ErrProtocol { // превышено окно приёма: валим сессию
				return err
			}
			if err == errAfterFin {
				s.killStream(st, reasonProtocol)
			}
		}
		return nil
	}
	st := s.stream(h.Stream)
	if st == nil {
		// Поток уже сброшен (CLOSE в пути): кадры, отправленные до CLOSE,
		// просто отбрасываем — но окно соединения за них возвращаем, иначе
		// кредит пира тает на каждом Reset. Это не нарушение протокола,
		// иначе сессия падала бы после каждого Reset.
		if n := len(p); n > 0 {
			wu := proto.WUPayload(0, uint32(n))
			s.trySend(proto.Header{Type: proto.TypeWU}, wu[:])
		}
		return nil
	}
	if err := st.deliver(p, fin); err != nil {
		switch err {
		case ErrProtocol: // превышено окно приёма: пир нарушил протокол
			return err
		case errAfterFin: // данные после чистого FIN: виноват один поток
			s.killStream(st, reasonProtocol)
		}
	}
	return nil
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
	t := time.NewTimer(s.pingEvery)
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
			if misses >= s.pingMiss {
				s.fail(ErrPingTimeout, reasonProtocol)
				return
			}
			s.ping()
		} else {
			misses = 0
		}
		prev = cur
		t.Reset(s.pingEvery)
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
