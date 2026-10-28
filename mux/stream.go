package mux

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"tuman/proto"
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

	rmu   sync.Mutex
	rq    []recvChunk
	rhead int
	rerr  error
	rfin  bool
	rwake chan struct{} // семафор: 1 токен = «проверь очередь»

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
				st.rmu.Unlock()
				if done != nil {
					pChunk.Put(done)
				}
				st.consumed(n)
				return n, nil
			}
		}
		if st.rerr != nil {
			err := st.rerr
			st.rmu.Unlock()
			return 0, err
		}
		st.rmu.Unlock()
		select {
		case <-st.rwake:
		case <-st.s.done:
			return 0, st.s.closedErr()
		}
		st.rmu.Lock()
	}
}

func (st *Stream) Write(p []byte) (int, error) {
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
	return st.write(context.Background(), h, p)
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
	err := s.send(proto.Header{Type: proto.TypeClose, Stream: st.id}, []byte{reasonClosed})
	st.resetLocal(ErrStream)
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
	s.mu.Lock()
	close(st.wait)
	st.wait = make(chan struct{})
	s.mu.Unlock()
	select {
	case st.rwake <- struct{}{}:
	default:
	}
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

// consumed возвращает окно пиру через WU при 25 % расхода (§5).
func (st *Stream) consumed(n int) {
	s := st.s
	s.mu.Lock()
	st.recvUsed += int32(n)
	st.recvPending -= int32(n)
	if st.recvPending < 0 {
		st.recvPending = 0
	}
	s.connUsed += int32(n)
	var sDelta, cDelta uint32
	if st.recvUsed >= winStream/4 {
		sDelta, st.recvUsed = uint32(st.recvUsed), 0
	}
	if s.connUsed >= winConn/4 {
		cDelta, s.connUsed = uint32(s.connUsed), 0
	}
	s.mu.Unlock()
	if sDelta > 0 {
		p := proto.WUPayload(st.id, sDelta)
		s.send(proto.Header{Type: proto.TypeWU}, p[:])
	}
	if cDelta > 0 {
		p := proto.WUPayload(0, cDelta)
		s.send(proto.Header{Type: proto.TypeWU}, p[:])
	}
}

// deliver кладёт данные в очередь приёма; вызывается только reader'ом.
func (st *Stream) deliver(p []byte, fin bool) error {
	st.rmu.Lock()
	if st.rerr != nil {
		err := st.rerr
		st.rmu.Unlock()
		if err == ErrStream {
			return ErrStream // поток сброшен нами: кадр в пути — не нарушение
		}
		return ErrProtocol // данные после чистого FIN — нарушение
	}
	if len(p) > 0 {
		st.push(p)
	}
	if len(p) > 0 {
		// под s.mu: сколько пришло и ещё не прочитано (нужно для возврата окна при сбросе)
		st.s.mu.Lock()
		st.recvPending += int32(len(p))
		st.s.mu.Unlock()
	}
	if fin {
		st.rfin = true
		st.rerr = io.EOF
	}
	select {
	case st.rwake <- struct{}{}:
	default:
	}
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
	select {
	case st.rwake <- struct{}{}:
	default:
	}
	st.rmu.Unlock()
	st.maybeFree()
}

func (st *Stream) maybeFree() {
	st.rmu.Lock()
	both := st.rfin && st.sfin.Load()
	st.rmu.Unlock()
	if both {
		st.s.drop(st)
	}
}
