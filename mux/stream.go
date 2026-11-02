package mux

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/tuman/proto"
)

type recvChunk struct {
	buf *chunkBuf
	n   int // записано
	off int // прочитано
}

type Stream struct {
	s   *Session
	id  uint16
	tgt []byte
	udp bool // датаграммный поток (SOCKS5 UDP ASSOCIATE)
	ip  bool // поток IP-пакетов (режим TUN)

	rmu   sync.Mutex
	rq    []recvChunk
	rhead int
	rerr  error
	rfin  bool
	rwake chan struct{} // семафор: 1 токен = «проверь очередь»

	// под rmu: дедлайн чтения. Срабатывая, он кидает токен в rwake — тот же
	// семафор, что и у данных, поэтому select в Read не подорожал.
	rdl    time.Time
	rdlGen uint64 // поколение: таймер прошлого поколения не стреляет
	rdlTmr *time.Timer

	// под s.mu
	sendWin     int32
	recvUsed    int32
	recvPending int32 // доставлено приложению, но ещё не прочитано
	wait        chan struct{}

	sfin   atomic.Bool
	urgent atomic.Bool
}

// Target — адресный блок §3, с которым поток открыт.
func (st *Stream) Target() []byte { return st.tgt }

// IsUDP — поток датаграммный (открыт с proto.FlagUDP).
func (st *Stream) IsUDP() bool { return st.udp }

// IsIP — поток несёт IP-пакеты (открыт с proto.FlagIP, режим TUN).
func (st *Stream) IsIP() bool { return st.ip }

func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.rmu.Lock()
	for {
		if st.rhead < len(st.rq) {
			c := &st.rq[st.rhead]
			n := copy(p, c.buf[c.off:c.n])
			if n > 0 {
				c.off += n
				var done *chunkBuf
				if c.off == c.n {
					done = c.buf
					st.rq[st.rhead] = recvChunk{}
					st.rhead++
					st.compact()
				}
				drained := st.rhead == len(st.rq)
				st.rmu.Unlock()
				if done != nil {
					pChunk.Put(done)
				}
				st.consumed(n, drained)
				return n, nil
			}
		}
		if st.rerr != nil {
			err := st.rerr
			st.rmu.Unlock()
			return 0, err
		}
		// Истёкший дедлайн проверяем до блокировки: данные из очереди важнее.
		expired := st.readExpired()
		st.rmu.Unlock()
		if expired {
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case <-st.rwake:
		case <-st.s.done:
			return 0, st.s.closedErr()
		}
		st.rmu.Lock()
	}
}

// readExpired (под rmu) сообщает, что дедлайн чтения истёк, и снимает его:
// следующий Read снова блокируется, а не спотыкается о мёртвый дедлайн.
func (st *Stream) readExpired() bool {
	if st.rdl.IsZero() || st.rdl.After(time.Now()) {
		return false
	}
	st.rdl = time.Time{}
	if st.rdlTmr != nil {
		st.rdlTmr.Stop()
		st.rdlTmr = nil
	}
	return true
}

// kick (под rmu) будит блокирующий Read: данные пришли или дедлайн истёк.
func (st *Stream) kick() {
	select {
	case st.rwake <- struct{}{}:
	default:
	}
}

// SetReadDeadline взводит дедлайн чтения: по его истечении блокирующий Read
// вернёт os.ErrDeadlineExceeded. Нулевое время снимает дедлайн, повторный
// вызов заменяет прежний таймер.
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	if st.rdlTmr != nil {
		st.rdlTmr.Stop()
		st.rdlTmr = nil
	}
	st.rdl = t
	st.rdlGen++
	switch d := time.Until(t); {
	case t.IsZero():
	case d <= 0:
		st.kick()
	default:
		gen := st.rdlGen
		st.rdlTmr = time.AfterFunc(d, func() {
			st.rmu.Lock()
			if st.rdlGen == gen { // таймер своего поколения: чужой не стреляет
				st.rdlTmr = nil
				st.kick()
			}
			st.rmu.Unlock()
		})
	}
	return nil
}

// WriteContext — Write, у которого ожидание окна отменяется ctx.
func (st *Stream) WriteContext(ctx context.Context, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if st.sfin.Load() {
		return 0, ErrStream
	}
	h := proto.Header{Type: proto.TypeData, Stream: st.id}
	if st.urgent.Load() {
		h.Flags = proto.FlagUrgent
	}
	return st.write(ctx, h, p)
}

func (st *Stream) Write(p []byte) (int, error) {
	return st.WriteContext(context.Background(), p)
}

// Close — полузакрытие: FIN в свою сторону; поток освобождается после FIN пира.
func (st *Stream) Close() error {
	if st.sfin.Swap(true) {
		return nil
	}
	s := st.s
	s.mu.Lock()
	close(st.wait)
	st.wait = make(chan struct{})
	s.mu.Unlock()
	err := s.send(proto.Header{Type: proto.TypeFin, Stream: st.id}, nil)
	st.maybeFree()
	return err
}

// Reset рвёт поток: CLOSE пиру + локальная очистка. В отличие от Close (FIN),
// говорит пиру «перестань слать», поэтому освобождает окно соединения.
func (st *Stream) Reset() error {
	s := st.s
	// Байты, доставленные нам, но не прочитанные приложением, надо вернуть
	// пиру как окно — иначе его connWin утекает и он замолкает навсегда.
	err := s.send(proto.Header{Type: proto.TypeClose, Stream: st.id}, []byte{reasonClosed})
	st.resetLocal(ErrStream)
	s.returnRecvWindow(st)
	return err
}

// resetLocal помечает поток закрытым с обеих сторон и будит читателей/писателей.
func (st *Stream) resetLocal(err error) {
	s := st.s
	st.rmu.Lock()
	if st.rerr == nil {
		st.rerr = err
	}
	st.rfin = true
	st.rmu.Unlock()
	st.sfin.Store(true) // писатели выходят из reserve с ErrStream
	s.mu.Lock()
	close(st.wait)
	st.wait = make(chan struct{})
	s.mu.Unlock()
	st.kick()
	s.drop(st)
}

// SetUrgent ставит URGENT на исходящие кадры потока.
func (st *Stream) SetUrgent(on bool) { st.urgent.Store(on) }

func (st *Stream) write(ctx context.Context, h proto.Header, p []byte) (int, error) {
	written := 0
	for {
		n, err := st.reserve(ctx, len(p))
		if err != nil {
			return written, err
		}
		h.Length = uint16(n)
		if err := st.s.send(h, p[:n]); err != nil {
			st.release(n)
			return written, err
		}
		written += n
		p = p[n:]
		if len(p) == 0 {
			return written, nil
		}
	}
}

// reserve списывает окно и ждёт, если оно кончилось.
func (st *Stream) reserve(ctx context.Context, max int) (int, error) {
	s := st.s
	for {
		s.mu.Lock()
		if st.sfin.Load() {
			s.mu.Unlock()
			return 0, ErrStream
		}
		// Сессия могла умереть: кредит выдавать нельзя, иначе Write вернёт nil,
		// а кадр уйдёт в очередь мёртвого writer'а (данные потеряны молча).
		if s.isClosed() {
			s.mu.Unlock()
			return 0, s.closedErr()
		}
		// Кадр без полезной нагрузки окно не тратит — иначе write() с пустым
		// payload ждал бы кредит вечно (OPEN потока IP-пакетов, FIN).
		if max == 0 {
			s.mu.Unlock()
			return 0, nil
		}
		if st.sendWin < 0 {
			st.sendWin = 0
		}
		if s.connWin < 0 {
			s.connWin = 0
		}
		n := min(max, s.max)
		if int32(n) > st.sendWin {
			n = int(st.sendWin)
		}
		if int32(n) > s.connWin {
			n = int(s.connWin)
		}
		if n > 0 {
			st.sendWin -= int32(n)
			s.connWin -= int32(n)
			s.mu.Unlock()
			return n, nil
		}
		ch, cch := st.wait, s.connWait
		s.mu.Unlock()
		select {
		case <-ch:
		case <-cch:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			return 0, s.closedErr()
		}
	}
}

func (st *Stream) release(n int) {
	s := st.s
	s.mu.Lock()
	st.sendWin += int32(n)
	s.connWin += int32(n)
	s.mu.Unlock()
}

// consumed возвращает окно пиру через WU при 1/8 расхода (§5).
func (st *Stream) consumed(n int, drained bool) {
	s := st.s
	s.mu.Lock()
	st.recvUsed += int32(n)
	st.recvPending -= int32(n)
	if st.recvPending < 0 {
		st.recvPending = 0
	}
	if s.recvTotal -= int32(n); s.recvTotal < 0 {
		s.recvTotal = 0
	}
	s.connUsed += int32(n)
	var sDelta, cDelta uint32
	// Порог 1/8 окна; при опустевшей очереди хвост отдаём раньше, но не мельче
	// 1/64 окна — иначе на каждый Read уходит кадр WU и трафик растёт впустую.
	tailMin := int32(winStream / 64)
	if st.recvUsed >= winStream/8 || (drained && st.recvUsed >= tailMin) {
		sDelta, st.recvUsed = uint32(st.recvUsed), 0
	}
	if s.connUsed >= winConn/8 || (drained && s.connUsed >= tailMin) {
		cDelta, s.connUsed = uint32(s.connUsed), 0
	}
	s.mu.Unlock()

	// consumed вызывается из Read: блокирующий send здесь останавливает приём
	// целиком. Если очередь полна — возвращаем кредит в счётчики и отдадим
	// при следующем чтении.
	if sDelta > 0 {
		p := proto.WUPayload(st.id, sDelta)
		if !s.trySend(proto.Header{Type: proto.TypeWU}, p[:]) {
			s.mu.Lock()
			st.recvUsed += int32(sDelta)
			s.mu.Unlock()
		}
	}
	if cDelta > 0 {
		p := proto.WUPayload(0, cDelta)
		if !s.trySend(proto.Header{Type: proto.TypeWU}, p[:]) {
			s.mu.Lock()
			s.connUsed += int32(cDelta)
			s.mu.Unlock()
		}
	}
}

// errAfterFin — данные после чистого FIN: рвём поток, но не сессию.
var errAfterFin = errors.New("mux: данные после FIN")

// deliver кладёт данные в очередь приёма; вызывается только reader'ом.
func (st *Stream) deliver(p []byte, fin bool) error {
	st.rmu.Lock()
	if st.rerr != nil {
		err := st.rerr
		st.rmu.Unlock()
		if err == ErrStream {
			return ErrStream // поток сброшен нами: кадр в пути — не нарушение
		}
		return errAfterFin // данные после чистого FIN — виноват только поток
	}
	if n := len(p); n > 0 {
		// под s.mu и ДО push: пир, игнорирующий окна, не должен набить
		// очередь приёма целиком (иначе одна сессия кладёт сервер по памяти).
		s := st.s
		s.mu.Lock()
		if st.recvPending+int32(n) > winStream || s.recvTotal+int32(n) > s.recvWin {
			s.mu.Unlock()
			st.rmu.Unlock()
			return ErrProtocol
		}
		st.recvPending += int32(n)
		s.recvTotal += int32(n)
		s.mu.Unlock()
		st.push(p)
	}
	if fin {
		st.rfin = true
		st.rerr = io.EOF
	}
	st.kick()
	st.rmu.Unlock()
	if fin {
		st.maybeFree()
	}
	return nil
}

func (st *Stream) push(p []byte) {
	if n := len(st.rq); n > st.rhead {
		c := &st.rq[n-1]
		if len(c.buf)-c.n >= len(p) {
			copy(c.buf[c.n:], p)
			c.n += len(p)
			return
		}
	}
	cb := pChunk.Get().(*chunkBuf)
	copy(cb[:], p)
	st.rq = append(st.rq, recvChunk{buf: cb, n: len(p)})
}

func (st *Stream) compact() {
	if st.rhead > 16 && st.rhead*2 >= len(st.rq) {
		n := copy(st.rq, st.rq[st.rhead:])
		st.rq = st.rq[:n]
		st.rhead = 0
	}
}

func (st *Stream) remoteFin() {
	st.rmu.Lock()
	if st.rfin {
		st.rmu.Unlock()
		return
	}
	st.rfin = true
	if st.rerr == nil {
		st.rerr = io.EOF
	}
	st.kick()
	st.rmu.Unlock()
	st.maybeFree()
}

func (st *Stream) maybeFree() {
	st.rmu.Lock()
	both := st.rfin && st.sfin.Load()
	st.rmu.Unlock()
	if both {
		// Поток уходит из таблицы: недочитанный кредит обязан вернуться пиру,
		// иначе connWin тает и новые потоки встают навсегда.
		st.s.returnRecvWindow(st)
		st.s.drop(st)
	}
}
