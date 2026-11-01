package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kshishtovsky/tuman/client"
	"github.com/kshishtovsky/tuman/shaper"
)

// config — плоский tmnc.toml. Ендпоинты: servers = ["host1:port", "host2:port"]
// плюс общий sni и опционально servers_sni = ["a", "b"] (столько же значений,
// что servers; пустая строка — взять общий sni). Старое поле server = "host:port"
// работает как список из одного ендпоинта.
type config struct {
	Server      string     // legacy: один ендпоинт (обратная совместимость)
	Servers     []endpoint // servers[] в конфиге или один из Server
	SNI         string
	PSKFile     string
	Insecure    bool          // только для тестов: без проверки серта
	AuthV2      bool          // AUTH v2: MAC сервера, ключ на сессию
	SocksListen string        // 127.0.0.1:1080
	SocksAuth   string        // "user:pass"; пусто — метод 0x00
	Conns       int           // размер пула TCP-соединений суммарно (1..8)
	CoolDown    time.Duration // пауза ендпоинта; 0 — 30 с (тесты задают короче)
	Profile     string        // форма трафика: off|browse|video|bulk|voice
	RoutesFile  string        // путь к routes.toml; пусто — всё в туннель
	Dialer      *net.Dialer   // не из TOML: встраивающий процесс кладёт сюда protect
}

// endpoint — один сервер и SNI под ним (у ендпоинтов SNI может отличаться).
type endpoint struct {
	addr string
	sni  string
}

// parseTOML — плоский key = value; вложенных таблиц в конфиге клиента нет.
func parseTOML(data []byte) (map[string]string, error) {
	m := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("строка %d: нет '='", i+1)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			s, err := strconv.Unquote(v)
			if err != nil {
				// Windows-путь вида "C:\Users\x" — невалидный TOML-escape;
				// берём содержимое как есть, чтобы конфиг не падал на бэкслэшах.
				if strings.HasSuffix(v, `"`) && len(v) >= 2 {
					s = v[1 : len(v)-1]
				} else {
					return nil, fmt.Errorf("строка %d: %w", i+1, err)
				}
			}
			v = s
		} else if j := strings.IndexByte(v, '#'); j >= 0 { // shortcut: '#' в незакавыченном значении — только комментарий
			v = strings.TrimSpace(v[:j])
		}
		m[k] = v
	}
	return m, nil
}

// splitList — однострочный TOML-массив: ["a:443", "b:443"].
// shortcut: запятая внутри элемента не поддержана — адреса и SNI её не содержат.
func splitList(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return nil, errors.New(`нужен массив ["a", "b"]`)
	}
	var out []string
	for _, p := range strings.Split(v[1:len(v)-1], ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, `"`) {
			s, err := strconv.Unquote(p)
			if err != nil {
				if len(p) < 2 || !strings.HasSuffix(p, `"`) {
					return nil, err
				}
				s = p[1 : len(p)-1]
			}
			p = s
		}
		out = append(out, p)
	}
	return out, nil
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	insecure, err := strconv.ParseBool(m["insecure"])
	if err != nil && m["insecure"] != "" {
		return nil, fmt.Errorf("insecure: %w", err)
	}
	authV2, err := strconv.ParseBool(m["auth_v2"])
	if err != nil && m["auth_v2"] != "" {
		return nil, fmt.Errorf("auth_v2: %w", err)
	}
	c := &config{
		SNI:         m["sni"],
		PSKFile:     m["psk_file"],
		Insecure:    insecure,
		AuthV2:      authV2,
		SocksListen: m["socks_listen"],
		SocksAuth:   m["socks_auth"],
		Profile:     m["profile"],
		RoutesFile:  m["routes_file"],
	}
	if c.Profile == "" {
		c.Profile = string(shaper.Off)
	}
	if !shaper.Profile(c.Profile).Valid() {
		return nil, fmt.Errorf("profile %q: off|browse|video|bulk|voice", c.Profile)
	}
	// servers[] — основной список; server — обратная совместимость (один ендпоинт).
	addrs := []string{m["server"]}
	if v := m["servers"]; v != "" {
		if addrs, err = splitList(v); err != nil {
			return nil, fmt.Errorf("servers: %w", err)
		}
	}
	var snis []string
	if v := m["servers_sni"]; v != "" {
		if snis, err = splitList(v); err != nil {
			return nil, fmt.Errorf("servers_sni: %w", err)
		}
		if len(snis) != len(addrs) {
			return nil, fmt.Errorf("servers_sni: %d значений на %d серверов", len(snis), len(addrs))
		}
	}
	if len(addrs) == 0 || addrs[0] == "" {
		return nil, errors.New("нужны servers (список) и psk_file")
	}
	if c.PSKFile == "" {
		return nil, errors.New("нужен psk_file")
	}
	for i, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return nil, fmt.Errorf("servers[%d]: %w", i, err)
		}
		sni := c.SNI
		if len(snis) > 0 && snis[i] != "" {
			sni = snis[i]
		}
		if sni == "" {
			sni = host
		}
		c.Servers = append(c.Servers, endpoint{addr: a, sni: sni})
	}
	c.Server = addrs[0]
	if c.SNI == "" {
		c.SNI = c.Servers[0].sni
	}
	if c.SocksListen == "" {
		c.SocksListen = "127.0.0.1:1080"
	}
	host, _, err := net.SplitHostPort(c.SocksListen)
	if err != nil {
		return nil, fmt.Errorf("socks_listen: %w", err)
	}
	// Не loopback без пароля — открытый прокси в сеть (и в туннель) для всех.
	if ip := net.ParseIP(host); c.SocksAuth == "" && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("socks_listen %s без socks_auth: прокси был бы открыт в сеть", c.SocksListen)
	}
	c.Conns = min(client.DefaultConns, 2*len(c.Servers))
	if v := m["conns"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > min(client.MaxConns, 2*len(c.Servers)) {
			return nil, fmt.Errorf("conns: нужно 1..%d (не больше 2 на ендпоинт)",
				min(client.MaxConns, 2*len(c.Servers)))
		}
		c.Conns = n
	}
	return c, nil
}

// loadPSK: 64 hex-символа или 32 сырых байта.
func loadPSK(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if s := strings.TrimSpace(string(b)); len(s) == 64 {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	if len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("psk: нужно 32 байта или 64 hex-символа")
}
