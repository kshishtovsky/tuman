package shaper

import (
	"testing"

	"github.com/kshishtovsky/tuman/proto"
)

func benchmark(b *testing.B, pr Profile, payload int) {
	snk := &sink{quiet: true} // без копий: мерим только шейпер
	s := New(snk, Config{Profile: pr})
	defer s.Close()
	rec := dataFrame(payload, 0)
	b.SetBytes(int64(len(rec)))
	b.ReportAllocs()
	b.ResetTimer()
	var headSent, headPad int64
	for i := 0; i < b.N; i++ {
		if headSent == 0 && s.sent >= earlyLimit { // конец начальной фазы
			headSent, headPad = s.sent, s.padded
		}
		if _, err := s.Write(rec); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	total := s.sent + s.padded
	if total > 0 {
		b.ReportMetric(float64(s.padded)/float64(total)*100, "pad%")
	}
	if headSent > 0 {
		b.ReportMetric(float64(headPad)/float64(headSent+headPad)*100, "pad_head%")
	}
}

func BenchmarkBrowse(b *testing.B)      { benchmark(b, Browse, proto.MaxPayload-8) } // типичная запись mux
func BenchmarkOff(b *testing.B)         { benchmark(b, Off, proto.MaxPayload-8) }
func BenchmarkBrowseSmall(b *testing.B) { benchmark(b, Browse, 200) } // мелкая фаза — тут паддинг работает
