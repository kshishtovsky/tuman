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

	"github.com/kshishtovsky/tuman/client"
	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
	"github.com/kshishtovsky/tuman/route"
)

const (
	dialTimeout = 10 * time.Second // прямое соединение мимо туннеля
)

type proxy struct {
	cfg    *config
	con    *client.Client
	rt     *route.Table
	log    *slog.Logger
	ln     net.Listener
	dialer *net.Dialer   // тот же Dialer, что у пула: Android вешает в него protect
	sem    chan struct{} // предел одновременных SOCKS-сессий
	tun    *tunMode      // nil — режим TUN не включён
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
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{Timeout: dialTimeout}
	}
	rt, err := route.LoadFile(cfg.RoutesFile)
	if err != nil {
		return nil, err
	}
	eps := make([]client.Endpoint, len(cfg.Servers))
	for i, e := range cfg.Servers {
		eps[i] = client.Endpoint{Addr: e.addr, SNI: e.sni, QUIC: e.quic}
	}
	con, err := client.New(client.Config{
		Servers:     eps,
		PSK:         psk,
		SNI:         cfg.SNI,
		Insecure:    cfg.Insecure,
		AuthV2:      cfg.AuthV2,
		Conns:       cfg.Conns,
		Profile:     cfg.Profile,
		Fingerprint: cfg.Fingerprint,
		Cooldown:    cfg.CoolDown,
		Dialer:      cfg.Dialer,
		Logger:      log,
	})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		con.Close()
		return nil, err
	}
	p := &proxy{cfg: cfg, con: con, rt: rt, log: log, ln: ln,
		dialer: cfg.Dialer, sem: make(chan struct{}, maxSocksConns)}
	go p.serve()
	return p, nil
}

func (p *proxy) Addr() string { return p.ln.Addr().String() }

func (p *proxy) Close() {
	p.ln.Close()
	if p.tun != nil {
		p.tun.Close()
	}
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
