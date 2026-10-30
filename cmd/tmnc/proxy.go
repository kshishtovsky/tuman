// SOCKS5-клиент TMN/1: вся работа с туннелем — в пакете client, здесь только
// флаги, конфиг, SOCKS5, маршруты и шейпер.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"tuman/client"
	"tuman/mux"
	"tuman/proto"
	"tuman/route"
)

const (
	dialTimeout = 10 * time.Second
	alpn        = "h2"               // §1: мимикрия под браузер
	authLabel   = "TMN1-AUTH-RANDOM" // §4: exporter вместо client_random
	// Одно TCP-соединение упирается в своё окно (~290 Мбит/с на RTT 55 мс),
	// 4 соединения дают полосу маршрута (замерено iperf3: 227 -> 418 Мбит/с).
	defaultConns = 4
	maxConns     = 8
)

type proxy struct {
	cfg *config
	con *client.Client
	rt  *route.Table
	log *slog.Logger
	ln  net.Listener
}

func start(cfg *config, psk []byte, log *slog.Logger) (*proxy, error) {
	// legacy-конфиг: только server — список из одного ендпоинта
	if len(cfg.Servers) == 0 {
		if cfg.Server == "" {
			return nil, errors.New("нет ни одного ендпоинта")
		}
		cfg.Servers = []endpoint{{addr: cfg.Server, sni: cfg.SNI}}
	}
	if cfg.Insecure {
		log.Warn("проверка сертификата отключена (insecure)")
	}
	rt, err := route.LoadFile(cfg.RoutesFile)
	if err != nil {
		return nil, err
	}
	eps := make([]client.Endpoint, len(cfg.Servers))
	for i, e := range cfg.Servers {
		eps[i] = client.Endpoint{Addr: e.addr, SNI: e.sni}
	}
	con, err := client.New(client.Config{
		Servers:  eps,
		PSK:      psk,
		SNI:      cfg.SNI,
		Insecure: cfg.Insecure,
		Conns:    cfg.Conns,
		Profile:  cfg.Profile,
		Cooldown: cfg.CoolDown,
		Logger:   log,
	})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		con.Close()
		return nil, err
	}
	p := &proxy{cfg: cfg, con: con, rt: rt, log: log, ln: ln}
	go p.serve()
	return p, nil
}

func (p *proxy) Addr() string { return p.ln.Addr().String() }

func (p *proxy) Close() {
	p.ln.Close()
	p.con.Close()
}

// reason — короткая причина для лога: ни адресов, ни SNI, ни целей.
func reason(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, proto.ErrAuth):
		return "auth"
	case errors.Is(err, mux.ErrHandshake), errors.Is(err, mux.ErrProtocol), errors.Is(err, mux.ErrPingTimeout):
		return "protocol"
	}
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return "tls"
	}
	return "network"
}
