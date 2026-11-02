package shaper

import (
	"io"
	"testing"

	"github.com/kshishtovsky/tuman/proto"
)

func benchmark(b *testing.B, pr Profile, sink io.ReadWriter, payload int) {
	s := New(sink, Config{Profile: pr})
	defer s.Close()
	rec := dataFrame(payload, 0)
	b.SetBytes(int64(len(rec)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Write(rec); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if total := s.sent + s.padded; total > 0 {
		b.ReportMetric(float64(s.padded)/float64(total)*100, "pad%")
	}
}

// nullSink — inner без работы: меряет только сам шейпер, как прежний quiet-sink.
type nullSink struct{}

func (nullSink) Write(p []byte) (int, error) { return len(p), nil }
func (nullSink) Read(p []byte) (int, error)  { return 0, io.EOF }

// copySink — прокси TLS: настоящий inner копирует байты (шифрование, syscall).
type copySink struct{ buf []byte }

func (c *copySink) Write(p []byte) (int, error) { c.buf = append(c.buf[:0], p...); return len(p), nil }
func (c *copySink) Read(p []byte) (int, error)  { return 0, io.EOF }

func BenchmarkBrowse(b *testing.B) {
	benchmark(b, Browse, nullSink{}, proto.MaxPayload-8)
}

// BenchmarkBrowseTLS — та же нагрузка, но inner копирует: видно, сколько
// шейпер добавляет к работе, которую в проде и так делает TLS.
func BenchmarkBrowseTLS(b *testing.B) {
	benchmark(b, Browse, &copySink{}, proto.MaxPayload-8)
}

// BenchmarkTLSOnly — тот же inner с копированием, но без шейпера: база для
// доли шейпера в пайплайне.
func BenchmarkTLSOnly(b *testing.B) {
	c := &copySink{}
	rec := dataFrame(proto.MaxPayload-8, 0)
	b.SetBytes(int64(len(rec)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Write(rec)
	}
}

func BenchmarkOff(b *testing.B) {
	benchmark(b, Off, nullSink{}, proto.MaxPayload-8)
}

// BenchmarkBrowseSmall — мелкая запись mux, тут работает коалесинг.
func BenchmarkBrowseSmall(b *testing.B) {
	benchmark(b, Browse, nullSink{}, 200)
}
