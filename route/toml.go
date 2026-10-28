package route

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadFile читает правила из TOML. Пустой путь — пустая таблица: всё в туннель.
func LoadFile(path string) (*Table, error) {
	if path == "" {
		return New(nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return New(rules)
}

// Parse — минимальный TOML: [[rule]] и key = "строка" | ["строка", ...].
// Полный TOML не нужен: в файле маршрутов только массивы строк.
// Нет action — правило остаётся tunnel (no-op), это безопасно.
func Parse(data []byte) ([]Rule, error) {
	var rules []Rule
	var cur *Rule
	p := &parser{s: string(data)}
	for {
		p.skip()
		if p.eof() {
			return rules, nil
		}
		if p.s[p.i] == '[' {
			name, err := p.section()
			if err != nil {
				return nil, err
			}
			if name != "rule" {
				return nil, fmt.Errorf("позиция %d: неизвестная таблица [[%s]]", p.i, name)
			}
			rules = append(rules, Rule{})
			cur = &rules[len(rules)-1]
			continue
		}
		if cur == nil {
			return nil, errors.New("ключ вне [[rule]]")
		}
		k, err := p.name()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.eof() || p.s[p.i] != '=' {
			return nil, fmt.Errorf("позиция %d: ждали '=' после %q", p.i, k)
		}
		p.i++
		switch k {
		case "action":
			s, err := p.str()
			if err != nil {
				return nil, err
			}
			if cur.Action, err = parseAction(s); err != nil {
				return nil, err
			}
		case "domains":
			if cur.Domains, err = p.list(); err != nil {
				return nil, err
			}
		case "cidrs":
			if cur.CIDRs, err = p.list(); err != nil {
				return nil, err
			}
		case "ports":
			ss, err := p.list()
			if err != nil {
				return nil, err
			}
			for _, s := range ss {
				pr, err := ParsePortRange(s)
				if err != nil {
					return nil, err
				}
				cur.Ports = append(cur.Ports, pr)
			}
		default:
			return nil, fmt.Errorf("неизвестный ключ %q в [[rule]]", k)
		}
	}
}

// ParsePortRange — "443" или "8000-8100".
func ParsePortRange(s string) (PortRange, error) {
	a, b, isRange := strings.Cut(strings.TrimSpace(s), "-")
	from, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return PortRange{}, fmt.Errorf("порт %q: %w", s, err)
	}
	if !isRange {
		return PortRange{From: from, To: from}, nil
	}
	to, err := strconv.Atoi(strings.TrimSpace(b))
	if err != nil {
		return PortRange{}, fmt.Errorf("порт %q: %w", s, err)
	}
	return PortRange{From: from, To: to}, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) eof() bool { return p.i >= len(p.s) }

// skip переходит через пробелы, переводы строк и комментарии.
func (p *parser) skip() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			p.i++
		case c == '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

func (p *parser) section() (string, error) {
	if !strings.HasPrefix(p.s[p.i:], "[[") {
		return "", fmt.Errorf("позиция %d: ждали [[rule]]", p.i)
	}
	p.i += 2
	name, err := p.name()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(p.s[p.i:], "]]") {
		return "", fmt.Errorf("позиция %d: ждали ]]", p.i)
	}
	p.i += 2
	return name, nil
}

func (p *parser) name() (string, error) {
	start := p.i
	for p.i < len(p.s) && isName(p.s[p.i]) {
		p.i++
	}
	if start == p.i {
		return "", fmt.Errorf("позиция %d: ждали имя", start)
	}
	return p.s[start:p.i], nil
}

func (p *parser) str() (string, error) {
	p.skip()
	if p.eof() || p.s[p.i] != '"' {
		return "", fmt.Errorf("позиция %d: ждали строку в кавычках", p.i)
	}
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			if p.i >= len(p.s) {
				return "", errors.New("незакрытая строка")
			}
			switch p.s[p.i] {
			case '"', '\\':
				b.WriteByte(p.s[p.i])
				p.i++
			default:
				return "", fmt.Errorf("позиция %d: escape \\%c", p.i, p.s[p.i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", errors.New("незакрытая строка")
}

func (p *parser) list() ([]string, error) {
	p.skip()
	if p.eof() || p.s[p.i] != '[' {
		return nil, fmt.Errorf("позиция %d: ждали массив [", p.i)
	}
	p.i++
	var out []string
	for {
		p.skip()
		if p.eof() {
			return nil, errors.New("незакрытый массив")
		}
		switch p.s[p.i] {
		case ']':
			p.i++
			return out, nil
		case ',':
			p.i++
			continue
		}
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
}

func isName(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}
