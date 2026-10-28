package mux_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tuman/mux"
)

var (
	testPSK = bytes.Repeat([]byte{0x11}, 32)
	testExp = bytes.Repeat([]byte{0x22}, 32)
	target  = []byte{2, 3, 'a', 'b', 'c', 0, 80} // atyp=domain, "abc", port 80
)

func pair(tb testing.TB) (*mux.Session, *mux.Session) {
	tb.Helper()
	c, s := net.Pipe()
	errc := make(chan error, 1)
	var srv *mux.Session
	go func() {
		var err error
		srv, err = mux.New(s, mux.Config{PSK: testPSK, Exporter: testExp})
		errc <- err
	}()
	cli, err := mux.New(c, mux.Config{IsClient: true, PSK: testPSK, Exporter: testExp})
	if err != nil {
		tb.Fatalf("client New: %v", err)
	}
	if err := <-errc; err != nil {
		tb.Fatalf("server New: %v", err)
	}
	tb.Cleanup(func() {
		cli.Close()
		srv.Close()
	})
	return cli, srv
}

func echo(ctx context.Context, s *mux.Session, done *sync.WaitGroup) {
	done.Add(1)
	go func() {
		defer done.Done()
		for {
			st, err := s.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				io.Copy(st, st)
				st.Close()
			}()
		}
	}()
}

func TestEchoSingle(t *testing.T) {
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	echo(ctx, srv, &wg)

	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.Target(), target) {
		t.Fatalf("Target = %x", st.Target())
	}
	msg := bytes.Repeat([]byte("tuman-"), 1000)
	if n, err := st.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("эхо %d байт, ждали %d", len(got), len(msg))
	}
}

func TestEchoHundredStreams(t *testing.T) {
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	echo(ctx, srv, &wg)

	const (
		streams = 100
		size    = 8 << 10
	)
	var inner sync.WaitGroup
	inner.Add(streams)
	for i := 0; i < streams; i++ {
		go func(i int) {
			defer inner.Done()
			st, err := cli.OpenStream(ctx, target)
			if err != nil {
				t.Errorf("поток %d: %v", i, err)
				return
			}
			msg := bytes.Repeat([]byte{byte(i)}, size)
			if _, err := st.Write(msg); err != nil {
				t.Errorf("поток %d: Write: %v", i, err)
				return
			}
			st.Close()
			got, err := io.ReadAll(st)
			if err != nil {
				t.Errorf("поток %d: ReadAll: %v", i, err)
				return
			}
			if !bytes.Equal(got, msg) {
				t.Errorf("поток %d: эхо %d байт, ждали %d", i, len(got), size)
			}
		}(i)
	}
	inner.Wait()
}

// Полузакрытие: после FIN клиента чтение ответа продолжает работать.
func TestHalfClose(t *testing.T) {
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() {
		st, err := srv.AcceptStream(ctx)
		if err != nil {
			errc <- err
			return
		}
		b, err := io.ReadAll(st)
		if err != nil {
			errc <- err
			return
		}
		if _, err := st.Write(append([]byte("echo:"), b...)); err != nil {
			errc <- err
			return
		}
		errc <- st.Close()
	}()

	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll после полузакрытия: %v", err)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("ответ %q", got)
	}
	if err := <-errc; err != nil {
		t.Fatalf("сервер: %v", err)
	}
}

// Закрытие сессии посреди передачи: Read не виснет и возвращает ошибку.
func TestCloseMidTransfer(t *testing.T) {
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	accepted := make(chan *mux.Stream, 1)
	go func() {
		if st, err := srv.AcceptStream(ctx); err == nil {
			accepted <- st // не читаем: пусть окно заполнится
		}
	}()

	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	<-accepted
	go func() {
		buf := bytes.Repeat([]byte{7}, 1400)
		for {
			if _, err := st.Write(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	cli.Close()

	errc := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 64))
		errc <- err
	}()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Read вернул nil после Close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read завис после Close")
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("Write после Close вернул nil")
	}
}

// Отправитель не превышает окно потока 4 MiB.
func TestWindowNotExceeded(t *testing.T) {
	const winStream = 4 << 20
	cli, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	accepted := make(chan *mux.Stream, 1)
	go func() {
		if st, err := srv.AcceptStream(ctx); err == nil {
			accepted <- st
		}
	}()

	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	srvSt := <-accepted

	var sent atomic.Int64
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 1400)
		for i := 0; i < (8<<20)/len(buf); i++ {
			n, err := st.Write(buf)
			sent.Add(int64(n))
			if err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()

	time.Sleep(300 * time.Millisecond)
	if got := sent.Load(); got > winStream+1400 {
		t.Fatalf("в полёте %d байт при окне %d", got, winStream)
	} else if got < winStream/2 {
		t.Fatalf("застряло на %d байт, окно не выбирается", got)
	}

	// читаем параллельно: окно должно разблокировать запись
	nch := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, srvSt)
		nch <- n
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("клиент: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("запись не разблокировалась после WU")
	}
	if total := sent.Load(); total <= winStream {
		t.Fatalf("записано %d при окне %d", total, winStream)
	}
	st.Close()
	n := <-nch
	if n != sent.Load() {
		t.Fatalf("принято %d, отправлено %d", n, sent.Load())
	}
}

func TestAcceptContextCancel(t *testing.T) {
	_, srv := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := srv.AcceptStream(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptStream = %v, ждали context.Canceled", err)
	}
}

func TestOpenStreamBadTarget(t *testing.T) {
	cli, _ := pair(t)
	ctx := context.Background()
	for _, bad := range [][]byte{nil, {9}, {1, 0, 0}, {2, 40, 'a'}} {
		if _, err := cli.OpenStream(ctx, bad); err != mux.ErrTarget {
			t.Fatalf("target %x: %v, ждали ErrTarget", bad, err)
		}
	}
}

// Регресс: брошенный поток не должен съедать окно соединения.
// Симптом на живом VPS: после нескольких оборванных загрузок новые потоки
// вставали навсегда — окно 16 МиБ уходило в недочитанные данные.
func TestResetReturnsConnWindow(t *testing.T) {
	cli, srv := pair(t)
	defer cli.Close()
	defer srv.Close()

	// сервер: каждый принятый поток безостановочно пишет, пока не получит ошибку
	go func() {
		for {
			st, err := srv.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func(st *mux.Stream) {
				buf := make([]byte, 16<<10)
				for {
					if _, err := st.Write(buf); err != nil {
						return
					}
				}
			}(st)
		}
	}()

	// 6 потоков, в каждом ~2 МиБ в полёте, затем сброс: суммарно > окна 16 МиБ
	for i := 0; i < 6; i++ {
		st, err := cli.OpenStream(context.Background(), target)
		if err != nil {
			t.Fatalf("поток %d: %v", i, err)
		}
		time.Sleep(40 * time.Millisecond) // дать серверу заполнить окно
		if err := st.Reset(); err != nil {
			t.Fatalf("Reset %d: %v", i, err)
		}
	}

	// новый поток обязан открыться быстро, иначе окно утекло
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatalf("после 6 сбросов новый поток не открылся: %v", err)
	}
	st.Reset()
}
