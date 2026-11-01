package mux_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// pairV2 поднимает пару с AUTH v2 у клиента.
func pairV2(tb testing.TB, rc *proto.ReplayCache) (*mux.Session, *mux.Session) {
	tb.Helper()
	c, s := net.Pipe()
	errc := make(chan error, 1)
	var srv *mux.Session
	go func() {
		var err error
		srv, err = mux.New(s, mux.Config{PSK: testPSK, Exporter: testExp, Replay: rc})
		errc <- err
	}()
	cli, err := mux.New(c, mux.Config{IsClient: true, PSK: testPSK, Exporter: testExp, AuthV2: true})
	if err != nil {
		tb.Fatalf("client New (v2): %v", err)
	}
	if err := <-errc; err != nil {
		tb.Fatalf("server New (v2): %v", err)
	}
	tb.Cleanup(func() { cli.Close(); srv.Close() })
	return cli, srv
}

// v2-сессия работает как обычная: поток, данные в обе стороны.
func TestAuthV2SessionWorks(t *testing.T) {
	cli, srv := pairV2(t, proto.NewReplayCache())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		st, err := srv.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(st, st)
		st.Close()
	}()
	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("v2"), 1000)
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("данные искажены")
	}
}

// Обе стороны выводят ОДИН И ТОТ ЖЕ сессионный ключ, и он не совпадает с ключом
// другой пары: именно это доказывает, что ключ привязан к соединению.
func TestAuthV2KeyAgreement(t *testing.T) {
	rc := proto.NewReplayCache()
	cli, srv := pairV2(t, rc)
	kc, okc := cli.Key()
	ks, oks := srv.Key()
	if !okc || !oks {
		t.Fatal("v2-сессия без ключа")
	}
	if kc != ks {
		t.Fatal("сессионные ключи сторон не совпали")
	}

	cli2, srv2 := pairV2(t, rc)
	k2, _ := cli2.Key()
	s2, _ := srv2.Key()
	if k2 != s2 {
		t.Fatal("вторая пара: ключи сторон не совпали")
	}
	if k2 == kc {
		t.Fatal("ключ не различается между сессиями: привязки к соединению нет")
	}
}

// Старый клиент (v1) продолжает работать с сервером, который умеет v2.
func TestAuthV1ClientStillWorks(t *testing.T) {
	cli, srv := pair(t) // pair() — обычный v1
	if _, ok := cli.Key(); ok {
		t.Fatal("v1-сессия отдала ключ")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		st, err := srv.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(st, st)
		st.Close()
	}()
	st, err := cli.OpenStream(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1" {
		t.Fatalf("получено %q", got)
	}
}

// Сервер отвергает AUTH_OK-подделку: MITM без PSK не может выдать себя за сервера.
func TestAuthV2MITMRejected(t *testing.T) {
	c, s := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		buf := make([]byte, 8+proto.MaxPayload)
		h, p, err := proto.ReadFrame(s, buf)
		if err != nil || h.Type != proto.TypeAuth {
			return
		}
		// пир знает формат, но не PSK: подсовывает AUTH_OK с мусорным тегом
		fake := make([]byte, proto.AuthOKV2Len)
		fake[0], fake[1] = 0, 2
		copy(fake[2:10], p[10:18]) // nonce-эхо угадать может
		proto.WriteFrame(s, proto.Header{Type: proto.TypeAuthOK}, fake)
	}()
	_, err := mux.New(c, mux.Config{IsClient: true, PSK: testPSK, Exporter: testExp, AuthV2: true})
	if err == nil {
		t.Fatal("клиент принял AUTH_OK без валидного MAC: MITM проходит")
	}
	<-peerDone
}

// Реплей между сессиями ловится общим кэшем: один и тот же AUTH нельзя провести
// дважды, даже переподключившись.
func TestAuthV2ReplayAcrossSessions(t *testing.T) {
	rc := proto.NewReplayCache()
	priv, err := proto.NewEphemeralKeyV2()
	if err != nil {
		t.Fatal(err)
	}
	pub := proto.PublicKeyV2(priv)
	auth, err := proto.MakeAuthV2(testPSK, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c, s := net.Pipe()
		go func() { // кадр уходит асинхронно: сервер читает его сам
			proto.WriteFrame(c, proto.Header{Type: proto.TypeAuth}, auth)
		}()
		go func() { // вторая сессия не должна получить AUTH_OK, но читать надо, чтобы не встал writer
			buf := make([]byte, 8+proto.MaxPayload)
			for {
				if _, _, err := proto.ReadFrame(c, buf); err != nil {
					return
				}
			}
		}()
		_, err := mux.New(s, mux.Config{PSK: testPSK, Exporter: testExp, Replay: rc})
		if i == 0 && err != nil {
			t.Fatalf("первый AUTH отвергнут: %v", err)
		}
		if i == 1 && err == nil {
			t.Fatal("повторный AUTH принят: реплей между сессиями проходит")
		}
		c.Close()
	}
}
