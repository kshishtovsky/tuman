package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/kshishtovsky/tuman/mux"
)

// alpnQUIC — единственный протокол QUIC-ендпоинта, как у клиента.
const alpnQUIC = "tuman"

// serveQUIC — тот же туннель по QUIC. TLS 1.3 живёт внутри QUIC, поэтому второго
// TLS нет: mux идёт прямо в потоке, привязку к каналу даёт AUTH v2.
//
// Сайта-прикрытия здесь нет и быть не может: QUIC-ендпоинт объявляет один ALPN,
// и чужой клиент получает отказ на handshake. Прикрытие живёт на TCP-порту.
func (s *server) serveQUIC(ln *quic.Listener) error {
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Тот же лимит, что на TCP: закрытие молча, как загруженный сервер.
		if !s.lim.allow(c.RemoteAddr()) {
			c.CloseWithError(0, "")
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.CloseWithError(0, "")
			continue
		}
		s.nQUIC.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handleQUIC(c)
		}()
	}
}

// handleQUIC: одна сессия = одно QUIC-соединение и один поток.
func (s *server) handleQUIC(c *quic.Conn) {
	defer c.CloseWithError(0, "")
	ctx, cancel := context.WithTimeout(s.ctx, hsWait)
	defer cancel()
	st, err := c.AcceptStream(ctx)
	if err != nil {
		return // нет потока — молчание, как idle keep-alive на TCP
	}
	sess, err := mux.New(&quicCarrier{Stream: st, conn: c},
		mux.Config{PSK: s.psk.Load().([]byte), AuthV2: true})
	if err != nil {
		s.log.Debug("quic auth", "err", errKind(err))
		return
	}
	s.nTunnel.Add(1)
	defer sess.Close()
	s.pump(sess)
}

// quicCarrier — QUIC-поток как io.ReadWriter для mux; Close закрывает и
// соединение, иначе сокет и горутины quic-go остаются до idle-таймаута.
type quicCarrier struct {
	*quic.Stream
	conn *quic.Conn
}

func (q *quicCarrier) Close() error {
	err := q.Stream.Close()
	q.conn.CloseWithError(0, "")
	return err
}

// quicConf: mux сам пингует каждые 25 с, поэтому idle-таймаут QUIC должен быть
// больше — иначе QUIC закроет соединение раньше, чем mux заметит обрыв.
func quicConf() *quic.Config {
	return &quic.Config{MaxIdleTimeout: 2 * time.Minute}
}

// quicTLS — TLS-конфиг QUIC-ендпоинта: только TLS 1.3 и только наш ALPN.
func (s *server) quicTLS() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpnQUIC},
		Certificates: s.certs,
	}
}
