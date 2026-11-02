package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// echoServer — цель туннеля: возвращает всё, что получил.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln
}

func client(t *testing.T, addr string, psk []byte) *mux.Session {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		ServerName:         "secret.example", // SNI не должен попасть в лог сервера
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(30 * time.Second))
	s, err := mux.New(c, mux.Config{IsClient: true, PSK: psk, Exporter: exporterOf(t, c)})
	if err != nil {
		t.Fatalf("mux.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// 1 МБ в обе стороны через два конца mux поверх реального TLS-сервера.
func TestTunnelEcho(t *testing.T) {
	addr, _ := start(t)
	echo := echoServer(t)
	s := client(t, addr, testPSK)
	ctx := context.Background()

	host, port, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := proto.EncodeTarget(host, port)
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 1<<20)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}

	// два потока в одном соединении: мультиплексирование и независимость потоков
	for i := 0; i < 2; i++ {
		st, err := s.OpenStream(ctx, tgt)
		if err != nil {
			t.Fatalf("поток %d: %v", i, err)
		}
		if !bytes.Equal(st.Target(), tgt) {
			t.Fatalf("поток %d: target %x", i, st.Target())
		}
		if _, err := st.Write(msg); err != nil {
			t.Fatalf("поток %d: Write: %v", i, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(st, got); err != nil {
			t.Fatalf("поток %d: ReadFull: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("поток %d: байты не совпали", i)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("поток %d: Close: %v", i, err)
		}
	}
}

// Чужой PSK: сессия не открывается, на проводе — сайт-прикрытие (см. fallback_test).
func TestTunnelBadPSK(t *testing.T) {
	addr, _ := start(t)
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := mux.New(c, mux.Config{IsClient: true, PSK: bytes.Repeat([]byte{0x43}, 32), Exporter: exporterOf(t, c)}); err == nil {
		t.Fatal("сессия с чужим PSK открылась")
	}
}

// Обрыв сессии не вешает egress и не роняет сервер.
func TestTunnelSessionDrop(t *testing.T) {
	addr, _ := start(t)
	echo := echoServer(t)
	s := client(t, addr, testPSK)
	host, port, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := proto.EncodeTarget(host, port)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.OpenStream(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("x"))
	s.Close()
	if _, err := st.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read после Close вернул nil")
	}
	// сервер должен продолжать обслуживать новые соединения
	client(t, addr, testPSK)
}

// Ротация PSK (FR-12): новый ключ принимается без рестарта, старый после
// ротации — нет. Проверяется реальным рукопожатием, а не заглядыванием в поле.
func TestPSKRotation(t *testing.T) {
	addr, srv := start(t)
	e := echoServer(t)
	tgt, err := proto.EncodeTarget("127.0.0.1", portOf(t, e.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	// до ротации ключ работает
	st, err := client(t, addr, testPSK).OpenStream(context.Background(), tgt)
	if err != nil {
		t.Fatalf("до ротации: %v", err)
	}
	st.Close()

	next := bytes.Repeat([]byte{0x5a}, 32)
	srv.rotate(next)

	if newClientSession(addr, testPSK) != nil {
		t.Fatal("старый ключ принят после ротации")
	}
	c := client(t, addr, next)
	st, err = c.OpenStream(context.Background(), tgt)
	if err != nil {
		t.Fatalf("новый ключ после ротации: %v", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatalf("запись новым ключом: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(st, got); err != nil || string(got) != "ping" {
		t.Fatalf("эхо: %q %v", got, err)
	}
	st.Close()
}

// newClientSession — попытка открыть сессию; nil при отказе сервера.
func newClientSession(addr string, psk []byte) *mux.Session {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	s, err := mux.New(c, mux.Config{IsClient: true, PSK: psk, Exporter: expOf(c)})
	if err != nil {
		c.Close()
		return nil
	}
	s.Close()
	return s
}

// expOf без *testing.T: нужен и в хелпере, который не имеет t.
func expOf(c *tls.Conn) []byte {
	cs := c.ConnectionState()
	exp, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil
	}
	return exp
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
