// tmns — сервер TMN/1: TLS 1.3, mux в серверном режиме и сайт-прикрытие для
// всего, что не является валидным AUTH (docs/07-proto-v1-spec.md §1, §4).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tuman/shaper"
)

type conf struct {
	Listen   string
	Cert     string
	Key      string
	PSKFile  string
	CoverDir string
	LogLevel string
	Profile  string // форма трафика: off|browse|video|bulk|voice
}

func main() {
	path := flag.String("config", "/etc/tmn/tmns.toml", "путь к конфигу")
	lvl := flag.String("log-level", "", "debug|info|warn|error (перекрывает log_level)")
	flag.Parse()

	if err := run(*path, *lvl); err != nil {
		slog.Error("tmns", "err", err)
		os.Exit(1)
	}
}

func run(path, lvl string) error {
	cfg, err := loadConf(path)
	if err != nil {
		return err
	}
	if lvl != "" {
		cfg.LogLevel = lvl
	}
	lg := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))

	psk, err := loadPSK(cfg.PSKFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return err
	}
	s, err := newServer(cfg, psk, []tls.Certificate{cert}, lg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	lg.Info("start", "listen", cfg.Listen)
	err = s.serve(ln)
	s.shutdown(15 * time.Second)
	lg.Info("stop", "tunnel", s.nTunnel.Load(), "cover", s.nCover.Load())
	return err
}

// loadConf — минимальный TOML: key = "value"; # — комментарий, [section] игнорируется.
func loadConf(path string) (conf, error) {
	c := conf{Listen: ":443", CoverDir: "/var/www/tmn", LogLevel: "info", Profile: "off"}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("%s:%d: ждали key = value", path, i+1)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "listen":
			c.Listen = v
		case "cert":
			c.Cert = v
		case "key":
			c.Key = v
		case "psk_file":
			c.PSKFile = v
		case "cover_dir":
			c.CoverDir = v
		case "log_level":
			c.LogLevel = v
		case "profile":
			c.Profile = v
		default:
			return c, fmt.Errorf("%s:%d: неизвестный ключ %q", path, i+1, k)
		}
	}
	if c.Cert == "" || c.Key == "" || c.PSKFile == "" {
		return c, errors.New("cert, key и psk_file обязательны")
	}
	if !shaper.Profile(c.Profile).Valid() {
		return c, fmt.Errorf("profile %q: off|browse|video|bulk|voice", c.Profile)
	}
	return c, nil
}

// loadPSK — 32 байта из файла: raw или hex (64 символа, допускается префикс 0x).
func loadPSK(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 64 || len(b) == 66 {
		if k, err := hex.DecodeString(strings.TrimPrefix(string(b), "0x")); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	if len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("%s: PSK должен быть 32 байта raw или 64 hex", path)
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
