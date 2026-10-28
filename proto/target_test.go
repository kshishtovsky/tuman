package proto

import "testing"

func TestTargetRoundtrip(t *testing.T) {
	cases := [][2]string{
		{"93.184.216.34", "443"},
		{"example.com", "80"},
		{"a", "1"},
		{"xn--80ak6aa92e.com", "65535"},
		{"2606:4700::6810:84e5", "8443"},
	}
	for _, c := range cases {
		b, err := EncodeTarget(c[0], c[1])
		if err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if n := TargetLen(b); n != len(b) {
			t.Fatalf("%v: TargetLen=%d, want %d", c, n, len(b))
		}
		h, p, err := DecodeTarget(b)
		if err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if h != c[0] || p != c[1] {
			t.Fatalf("got %s:%s, want %s:%s", h, p, c[0], c[1])
		}
	}
}

func TestTargetRejects(t *testing.T) {
	for _, c := range [][2]string{
		{"", "80"}, {"a", "0"}, {"a", "65536"}, {"a", "x"},
		{"very-long-" + string(make([]byte, 250)), "80"},
	} {
		if _, err := EncodeTarget(c[0], c[1]); err == nil {
			t.Fatalf("%v: ожидалась ошибка", c)
		}
	}
	for _, b := range [][]byte{
		nil, {}, {9}, {AtypIPv4, 1, 2, 3}, {AtypDomain, 0}, {AtypDomain, 5, 'a'},
		{AtypDomain, 1, 'a', 0, 0}, {AtypIPv6, 1, 2, 3},
	} {
		if _, _, err := DecodeTarget(b); err == nil {
			t.Fatalf("%v: ожидалась ошибка", b)
		}
		if TargetLen(b) != -1 {
			t.Fatalf("%v: TargetLen должен быть -1", b)
		}
	}
}

func TestTargetAllocBudget(t *testing.T) {
	// Разбор цели — один раз на поток, не в горячем пути пакета:
	// разрешаем 2 аллокации (net.IP.String + strconv.Itoa), но не больше.
	b, _ := EncodeTarget("example.com", "443")
	allocs := testing.AllocsPerRun(100, func() {
		_, _, _ = DecodeTarget(b)
	})
	if allocs > 2 {
		t.Fatalf("DecodeTarget аллоцирует больше бюджета: %.2f allocs/op", allocs)
	}
}
