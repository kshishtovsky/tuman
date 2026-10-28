package route

import (
	"os"
	"strings"
	"testing"
)

func must(t *testing.T, rules ...Rule) *Table {
	t.Helper()
	tb, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tb
}

// "example.com" ловит сам домен и поддомены, но не notexample.com.
func TestSuffix(t *testing.T) {
	tb := must(t, Rule{Domains: []string{"example.com"}, Action: Direct})
	cases := map[string]Action{
		"example.com":         Direct,
		"a.example.com":       Direct,
		"a.b.example.com":     Direct,
		"notexample.com":      Tunnel,
		"example.com.evil.ru": Tunnel,
		"com":                 Tunnel,
		"":                    Tunnel,
	}
	for host, want := range cases {
		if got := tb.Decide(host, 443); got != want {
			t.Errorf("%q: %v, ждали %v", host, got, want)
		}
	}
}

// "*.example.com" — та же форма правила, что и без звёздочки.
func TestWildcard(t *testing.T) {
	tb := must(t, Rule{Domains: []string{"*.example.com"}, Action: Block})
	for _, h := range []string{"example.com", "a.example.com"} {
		if got := tb.Decide(h, 443); got != Block {
			t.Errorf("%q: %v, ждали block", h, got)
		}
	}
	if got := tb.Decide("notexample.com", 443); got != Tunnel {
		t.Errorf("notexample.com: %v", got)
	}
}

func TestNormalizeHost(t *testing.T) {
	tb := must(t, Rule{Domains: []string{"Example.COM"}, Action: Direct})
	for _, h := range []string{"A.Example.com", "a.example.com.", "A.EXAMPLE.COM."} {
		if got := tb.Decide(h, 443); got != Direct {
			t.Errorf("%q: %v, ждали direct", h, got)
		}
	}
}

func TestCIDR(t *testing.T) {
	tb := must(t,
		Rule{CIDRs: []string{"10.0.0.0/8"}, Action: Direct},
		Rule{CIDRs: []string{"2001:db8::/32"}, Action: Block},
	)
	cases := []struct {
		host string
		want Action
	}{
		{"10.1.2.3", Direct},
		{"10.255.255.255", Direct},
		{"11.1.2.3", Tunnel},
		{"2001:db8::1", Block},
		{"2001:db8:1:2::3", Block},
		{"2001:db9::1", Tunnel},
		{"::1", Tunnel},
		// домен не резолвим: CIDR к нему не применяется
		{"10.0.0.1.nip.io", Tunnel},
	}
	for _, c := range cases {
		if got := tb.Decide(c.host, 443); got != c.want {
			t.Errorf("%q: %v, ждали %v", c.host, got, c.want)
		}
	}
}

// Первое совпавшее правило сверху выигрывает.
func TestPriority(t *testing.T) {
	tb := must(t,
		Rule{Domains: []string{"example.com"}, Action: Direct},
		Rule{Domains: []string{"a.example.com"}, Action: Block},
	)
	if got := tb.Decide("a.example.com", 443); got != Direct {
		t.Fatalf("a.example.com: %v, ждали direct (первое правило сверху)", got)
	}
	tb = must(t,
		Rule{Domains: []string{"a.example.com"}, Action: Block},
		Rule{Domains: []string{"example.com"}, Action: Direct},
	)
	if got := tb.Decide("a.example.com", 443); got != Block {
		t.Fatalf("a.example.com: %v, ждали block", got)
	}
}

func TestPorts(t *testing.T) {
	tb := must(t,
		Rule{Domains: []string{"example.com"}, Ports: []PortRange{{443, 443}}, Action: Direct},
		Rule{Ports: []PortRange{{8000, 8100}}, Action: Block},
	)
	cases := []struct {
		host string
		port int
		want Action
	}{
		{"example.com", 443, Direct},
		{"example.com", 80, Tunnel},
		{"other.com", 8000, Block},
		{"other.com", 8100, Block},
		{"10.0.0.1", 8050, Block},
		{"other.com", 8101, Tunnel},
		{"other.com", 7999, Tunnel},
	}
	for _, c := range cases {
		if got := tb.Decide(c.host, c.port); got != c.want {
			t.Errorf("%s:%d: %v, ждали %v", c.host, c.port, got, c.want)
		}
	}
}

func TestDecideNoAlloc(t *testing.T) {
	tb := must(t,
		Rule{Domains: []string{"example.com"}, Action: Direct},
		Rule{CIDRs: []string{"10.0.0.0/8"}, Action: Block},
	)
	tb.Decide("a.example.com", 443) // прогрев кеша
	if got := testing.AllocsPerRun(1000, func() { _ = tb.Decide("a.example.com", 443) }); got != 0 {
		t.Fatalf("Decide в кеше: %v аллокаций, ждали 0", got)
	}
}

func TestCache(t *testing.T) {
	tb := must(t, Rule{Domains: []string{"example.com"}, Action: Direct})
	for i := 0; i < 3; i++ {
		if got := tb.Decide("a.example.com", 443); got != Direct {
			t.Fatalf("попытка %d: %v", i, got)
		}
	}
	tb.mu.RLock()
	n := len(tb.cache)
	tb.mu.RUnlock()
	if n != 1 {
		t.Fatalf("в кеше %d записей, ждали 1", n)
	}

	// переполнение: новые решения не кешируются, старые живы
	for i := 0; i < cacheMax+50; i++ {
		tb.Decide("h"+strings.Repeat("x", i%3)+string(rune('a'+i%26))+".test", 80+i)
	}
	tb.mu.RLock()
	n = len(tb.cache)
	tb.mu.RUnlock()
	if n > cacheMax {
		t.Fatalf("кеш вырос до %d, потолок %d", n, cacheMax)
	}
}

func TestLoadFileEmpty(t *testing.T) {
	tb, err := LoadFile("")
	if err != nil {
		t.Fatalf("LoadFile(\"\"): %v", err)
	}
	for _, h := range []string{"example.com", "10.0.0.1", "::1"} {
		if got := tb.Decide(h, 443); got != Tunnel {
			t.Errorf("%q: %v, ждали tunnel по умолчанию", h, got)
		}
	}
}

func TestParse(t *testing.T) {
	src := `
# комментарий
[[rule]]
action = "direct"
domains = [
  "ya.ru",      # строка с комментарием
  "*.example.com",
]
cidrs = ["5.255.0.0/18", "2001:db8::/32"]
ports = ["443", "8000-8100"]

[[rule]]
action = "block"
ports = ["25"]
`
	rules, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("правил %d, ждали 2", len(rules))
	}
	r := rules[0]
	if r.Action != Direct || len(r.Domains) != 2 || len(r.CIDRs) != 2 || len(r.Ports) != 2 {
		t.Fatalf("правило 0: %+v", r)
	}
	if r.Ports[1] != (PortRange{8000, 8100}) {
		t.Fatalf("диапазон: %+v", r.Ports[1])
	}
	if rules[1].Action != Block || rules[1].Ports[0] != (PortRange{25, 25}) {
		t.Fatalf("правило 1: %+v", rules[1])
	}

	tb, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := tb.Decide("a.example.com", 443); got != Direct {
		t.Fatalf("a.example.com:443: %v", got)
	}
	if got := tb.Decide("google.com", 25); got != Block {
		t.Fatalf("google.com:25: %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	bad := map[string]string{
		"cidr":     "[[rule]]\naction = \"direct\"\ncidrs = [\"10.0.0.0/33\"]\n",
		"порт":     "[[rule]]\naction = \"direct\"\nports = [\"70000\"]\n",
		"порядок":  "[[rule]]\naction = \"direct\"\nports = [\"900-100\"]\n",
		"ключ":     "[[rule]]\naction = \"direct\"\ndomain = [\"a.ru\"]\n",
		"действие": "[[rule]]\naction = \"drop\"\n",
		"скобка":   "[[rule]]\naction = \"direct\"\ndomains = [\"a.ru\"\n",
		"таблица":  "[[route]]\naction = \"direct\"\n",
	}
	for name, src := range bad {
		rules, err := Parse([]byte(src))
		if err == nil {
			_, err = New(rules) // cidr, порты и диапазоны проверяет New
		}
		if err == nil {
			t.Errorf("%s: ошибки нет", name)
		}
	}
	// ошибка валидации доходит и через файл
	dir := t.TempDir()
	path := dir + "/bad.toml"
	if err := os.WriteFile(path, []byte("[[rule]]\ncidrs = [\"10.0.0.0/33\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile: ошибки нет на битый CIDR")
	}
}

// Пример RU-списка обязан грузиться и работать.
func TestLoadExample(t *testing.T) {
	tb, err := LoadFile("../examples/routes-ru.toml")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	cases := []struct {
		host string
		want Action
	}{
		{"gosuslugi.ru", Direct},
		{"lk.gosuslugi.ru", Direct},
		{"sberbank.ru", Direct},
		{"yandex.ru", Direct},
		{"google.com", Tunnel},
		{"github.com", Tunnel},
		{"77.88.55.88", Direct},
		{"8.8.8.8", Tunnel},
	}
	for _, c := range cases {
		if got := tb.Decide(c.host, 443); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.host, got, c.want)
		}
	}
	if len(tb.rules) < 5 {
		t.Fatalf("правил %d, ждали больше", len(tb.rules))
	}
}
