package mux_test

// Устойчивость сессии: окно приёма, возврат кредита, битые WU, переполнение
// очереди accept, исчерпание id, Close без io.Closer.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// rawServer поднимает сессию-сервер и отдаёт «клиентский» конец трубы,
// прошедший рукопожатие вручную: тест шлёт любые кадры мимо окон.
func rawServer(tb testing.TB) (*mux.Session, net.Conn) {
	tb.Helper()
	c, s := net.Pipe()
	errc := make(chan error, 1)
	var srv *mux.Session
	go func() {
		sess, err := mux.New(s, mux.Config{PSK: testPSK, Exporter: testExp})
		srv = sess
		errc <- err
	}()
	p, err := proto.MakeAuth(testPSK, testExp, time.Now())
	if err != nil {
		tb.Fatalf("MakeAuth: %v", err)
	}
	if err := proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, p); err != nil {
		tb.Fatalf("AUTH: %v", err)
	}
	var buf [8 + proto.MaxPayload]byte
	h, _, err := proto.ReadFrame(c, buf[:])
	if err != nil || h.Type != proto.TypeAuthOK {
		tb.Fatalf("рукопожатие: %v, тип %#x", err, h.Type)
	}
	if err := <-errc; err != nil {
		tb.Fatalf("server New: %v", err)
	}
	tb.Cleanup(func() {
		srv.Close()
		c.Close()
	})
	return srv, c
}

func writeFrame(tb testing.TB, c net.Conn, h proto.Header, p []byte) {
	tb.Helper()
	if err := proto.WriteFrame(c, h, p); err != nil {
		tb.Fatalf("кадр %#x: %v", h.Type, err)
	}
}

// syncFrames шлёт PING и ждёт его эхо: всё, что отправлено раньше, уже
// обработано reader'ом сессии.
func syncFrames(tb testing.TB, c net.Conn) {
	tb.Helper()
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	writeFrame(tb, c, proto.Header{Type: proto.TypePing}, nonce[:])
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var buf [8 + proto.MaxPayload]byte
	for {
		h, p, err := proto.ReadFrame(c, buf[:])
		if err != nil {
			tb.Fatalf("sync: %v", err)
		}
		if h.Type == proto.TypePing && bytes.Equal(p, nonce[:]) {
			return
		}
	}
}

// (a) Пир, игнорирующий окно приёма, валит только свою сессию — и до того,
// как в очередь приёма влезет больше окна (иначе один поток кладёт сервер).
func TestReceiveWindowEnforced(t *testing.T) {
	srv, c := rawServer(t)
	go io.Copy(io.Discard, c) // читаем исходящее, чтобы writer сессии не встал

	gone := make(chan struct{})
	go func() { // accept без чтения: данные копятся в очереди приёма
		for {
			if _, err := srv.AcceptStream(context.Background()); err != nil {
				close(gone)
				return
			}
		}
	}()

	writeFrame(t, c, proto.Header{Type: proto.TypeData, Flags: proto.FlagOpen, Stream: 1}, target)
	c.SetWriteDeadline(time.Now().Add(20 * time.Second))
	payload := make([]byte, proto.MaxPayload)
	h := proto.Header{Type: proto.TypeData, Stream: 1}
	const winStream = 8 << 20 // как в mux.go
	sent := 0
	for ; sent <= 32<<20; sent += len(payload) {
		if err := proto.WriteFrame(c, h, payload); err != nil {
			break // сессия умерла и закрыла трубу
		}
	}
	if sent <= winStream {
		t.Fatalf("принято %d байт при окне %d — сессия не упала", sent, winStream)
	}
	if sent > 12<<20 {
		t.Fatalf("в очередь приёма влезло %d байт при окне %d", sent, winStream)
	}
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("сессия не упала на превышении окна приёма")
	}
	if _, err := srv.AcceptStream(context.Background()); !errors.Is(err, mux.ErrProtocol) {
		t.Fatalf("AcceptStream после нарушения = %v, ждали ErrProtocol", err)
	}
}

// (b) Потоки, которые приложение закрывает не читая, возвращают окно
// соединения: иначе 32 x 1 МиБ подвешивают Write навсегда.
func TestAbandonedStreamsReturnWindow(t *testing.T) {
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // приложение принимает и сразу закрывает, ничего не читая
		for {
			st, err := srv.AcceptStream(ctx)
			if err != nil {
				return
			}
			st.Close()
		}
	}()

	payload := bytes.Repeat([]byte{7}, 1<<20)
	for i := 0; i < 32; i++ {
		st, err := cli.OpenStream(ctx, target)
		if err != nil {
			t.Fatalf("поток %d: %v", i, err)
		}
		if _, err := st.Write(payload); err != nil {
			t.Fatalf("поток %d: Write: %v", i, err)
		}
		st.Close()
	}

	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wcancel()
	st, err := cli.OpenStream(wctx, target)
	if err != nil {
		t.Fatalf("поток после 32 брошенных не открылся: %v", err)
	}
	if _, err := st.WriteContext(wctx, payload); err != nil {
		t.Fatalf("Write после 32 брошенных потоков: %v", err)
	}
}

// (c) WU с delta 2^31 не должен уводить окно в минус: Write обязан пройти.
func TestWUBogusDelta(t *testing.T) {
	srv, c := rawServer(t)
	writeFrame(t, c, proto.Header{Type: proto.TypeData, Flags: proto.FlagOpen, Stream: 1}, target)
	actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer acancel()
	st, err := srv.AcceptStream(actx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	h := proto.Header{Type: proto.TypeWU}
	connBad, streamBad := proto.WUPayload(0, 1<<31), proto.WUPayload(1, 1<<31)
	connOK, streamOK := proto.WUPayload(0, 1<<20), proto.WUPayload(1, 1<<20)
	// мусорный кредит, затем легальный — ровно как у присланной аудитом пары
	writeFrame(t, c, h, connBad[:])
	writeFrame(t, c, h, streamBad[:])
	writeFrame(t, c, h, connOK[:])
	writeFrame(t, c, h, streamOK[:])
	syncFrames(t, c)

	go io.Copy(io.Discard, c) // пир читает, иначе труба встанет и тест соврёт
	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wcancel()
	if _, err := st.WriteContext(wctx, bytes.Repeat([]byte{1}, 256<<10)); err != nil {
		t.Fatalf("Write после битого WU: %v", err)
	}
}

// (d) 300 OPEN без AcceptStream: лишние потоки получают CLOSE, сессия жива.
func TestAcceptQueueOverflowKeepsSession(t *testing.T) {
	const opens = 300
	const acceptCap = 256 // как в mux.go
	cli, srv := pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	streams := make([]*mux.Stream, 0, opens)
	for i := 0; i < opens; i++ {
		st, err := cli.OpenStream(ctx, target)
		if err != nil {
			t.Fatalf("OPEN %d: %v", i, err)
		}
		streams = append(streams, st)
	}

	// Последний поток обязан получить CLOSE: Write выходит с ErrStream.
	last := streams[opens-1]
	for {
		if _, err := last.Write([]byte("x")); errors.Is(err, mux.ErrStream) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("лишний поток не получил CLOSE")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Очередь accept цела: ровно acceptCap потоков дождались приложения.
	for i := 0; i < acceptCap; i++ {
		if _, err := srv.AcceptStream(ctx); err != nil {
			t.Fatalf("AcceptStream %d: %v", i, err)
		}
	}

	// Сессия жива: новый поток проходит с данными.
	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatalf("OpenStream после переполнения: %v", err)
	}
	peer, err := srv.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream после переполнения: %v", err)
	}
	msg := []byte("живой")
	if _, err := st.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Read = %q, %v", got, err)
	}
	select {
	case <-cli.Done():
		t.Fatal("сессия умерла после переполнения accept")
	default:
	}
}

// (e) Исчерпание id — не «мёртвая» сессия, а ErrExhausted: пул переподключится.
func TestOpenStreamExhausted(t *testing.T) {
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			if _, err := srv.AcceptStream(ctx); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 1<<14; i++ { // 1,3,...,0x7FFF
		if _, err := cli.OpenStream(ctx, target); err != nil {
			t.Fatalf("OPEN %d: %v", i, err)
		}
	}
	if _, err := cli.OpenStream(ctx, target); !errors.Is(err, mux.ErrExhausted) {
		t.Fatalf("OpenStream за 0x7FFF = %v, ждали ErrExhausted", err)
	}
}

type noCloser struct{ c net.Conn }

func (n noCloser) Read(p []byte) (int, error)  { return n.c.Read(p) }
func (n noCloser) Write(p []byte) (int, error) { return n.c.Write(p) }

// (f) Close на conn без io.Closer не висит: writer может стоять в conn.Write.
func TestCloseWithoutCloser(t *testing.T) {
	c, s := net.Pipe()
	peerStay := make(chan struct{})
	go func() {
		var buf [8 + proto.MaxPayload]byte
		if _, _, err := proto.ReadFrame(s, buf[:]); err != nil {
			return
		}
		if err := proto.WriteFrame(s, proto.Header{Type: proto.TypeAuthOK}, proto.MakeAuthOK(proto.MaxPayload, 32<<20, proto.CapUrgent)); err != nil {
			return
		}
		<-peerStay // дальше не читаем: writer клиента встанет в conn.Write
	}()
	t.Cleanup(func() {
		close(peerStay)
		c.Close()
		s.Close()
	})

	cli, err := mux.New(noCloser{c}, mux.Config{IsClient: true, PSK: testPSK, Exporter: testExp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cli.OpenStream(context.Background(), target); err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // writer успевает встать в conn.Write
	start := time.Now()
	cli.Close()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close занял %v при conn без io.Closer", d)
	}
}
