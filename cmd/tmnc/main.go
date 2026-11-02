// Команда tmnc — SOCKS5-клиент TMN/1: пул TLS-сессий на все потоки (FR-1, §5 дизайна).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kshishtovsky/tuman/tun"
)

func main() {
	cfgPath := flag.String("config", "tmnc.toml", "путь к конфигу")
	lvl := flag.String("log-level", "", "debug|info|warn|error")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*lvl)}))
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Error("конфиг", "err", err)
		os.Exit(1)
	}
	psk, err := loadPSK(cfg.PSKFile)
	if err != nil {
		log.Error("psk", "err", err)
		os.Exit(1)
	}
	p, err := start(cfg, psk, log)
	if err != nil {
		log.Error("SOCKS5 не запущен", "err", err)
		os.Exit(1)
	}
	log.Info("SOCKS5 слушает", "addr", cfg.SocksListen, "eps", len(cfg.Servers), "pool", cfg.Conns)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.Tun != "" {
		if err := p.startTun(ctx, cfg.Tun, cfg.TunAddr); err != nil {
			p.Close()
			log.Error("TUN не поднят", "err", err)
			os.Exit(1)
		}
		log.Info("TUN поднят", "dev", cfg.Tun, "addr", cfg.TunAddr, "mtu", tun.MTU)
	}
	<-ctx.Done()
	p.Close()
}

// parseLevel — тот же контракт, что у tmns; пустая строка = info.
func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
