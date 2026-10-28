package mux_test

import (
	"context"
	"io"
	"testing"
)

// Один поток, 64 MiB в одну сторону; MB/s печатает SetBytes.
func BenchmarkMuxThroughput(b *testing.B) {
	const total = 64 << 20
	cli, srv := pair(b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			st, err := srv.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				io.CopyN(io.Discard, st, total)
				st.Close()
			}()
		}
	}()

	payload := make([]byte, 64<<10)
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := cli.OpenStream(ctx, target)
		if err != nil {
			b.Fatal(err)
		}
		for n := 0; n < total; n += len(payload) {
			if _, err := st.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
		io.Copy(io.Discard, st) // ждём FIN = все байты дошли
	}
	b.StopTimer()
}
