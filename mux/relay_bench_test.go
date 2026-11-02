package mux_test

// Бенчмарк релея в форме реального горячего пути: mux-поток -> localhost TCP
// с SetWriteDeadline на каждую порцию, как в cmd/tmnc/socks.go. В отличие от
// BenchmarkMuxThroughput (net.Pipe), здесь видно стоимость syscall'ов и
// размеров чтения: дренаж чанков в Read поднял 32K-релей с ~200 до ~350-500 МБ/с.

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/proto"
)

// benchLoopback гоняет total байт из mux-потока в настоящий loopback-сокет,
// повторяя цикл релея: Write с дедлайном на каждую порцию.
func benchLoopback(b *testing.B, buf int) {
	const total = 32 << 20
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.CopyBuffer(io.Discard, c, make([]byte, 64<<10)); c.Close() }()
		}
	}()

	cli, srv := pair(b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			st, err := srv.AcceptStream(ctx)
			if err != nil {
				return
			}
			payload := make([]byte, 1400)
			for n := 0; n < total; n += len(payload) {
				if _, err := st.Write(payload); err != nil {
					return
				}
			}
			st.Close()
		}
	}()

	target, _ := proto.EncodeTarget("speed.cloudflare.com", "443")
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := cli.OpenStream(ctx, target)
		if err != nil {
			b.Fatal(err)
		}
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		relay(buf, c, st)
		c.Close()
	}
}

// relay — копия горячего пути cmd/tmnc/socks.go: дедлайн на каждую запись.
func relay(buf int, dst net.Conn, src io.Reader) {
	if buf == 0 {
		buf = 32 << 10
	}
	b := make([]byte, buf)
	for {
		n, err := src.Read(b)
		if n > 0 {
			if derr := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); derr == nil {
				if _, werr := dst.Write(b[:n]); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func BenchmarkRelayLoopback32K(b *testing.B) { benchLoopback(b, 32<<10) }
func BenchmarkRelayLoopback4K(b *testing.B)  { benchLoopback(b, 4<<10) }
