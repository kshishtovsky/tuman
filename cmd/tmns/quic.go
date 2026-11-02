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

// alpnQUIC — серверное предложение в порядке предпочтения. "h3" первым, как у
// настоящего HTTP/3-сервера (Go берёт первый общий протокол из этого списка);
// "tuman" — ALPN сборок ≤ v0.2.1: обязать всех обновиться разом нельзя, а
// отказ в handshake выключил бы туннель у старого парка.
var alpnQUIC = []string{"h3", "tuman"}

// serveQUIC — тот же туннель по QUIC. TLS 1.3 живёт внутри QUIC, поэтому второго
// TLS нет: mux идёт прямо в потоке, привязку к каналу даёт AUTH v2.
//
// Сайта-прикрытия здесь нет: h3 согласуется, иначе отказ на ALPN сам выдавал бы
// сервер, но браузер, открывший поток, получит молчание. Прикрытие живёт на
// TCP-порту.
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

// quicConf: транспортные параметры под браузер. mux сам пингует каждые 25 с,
// поэтому idle-таймаут QUIC должен быть больше.
func quicConf() *quic.Config {
	return &quic.Config{
		// Браузеры паддят Initial до 1350 Б; дефолт quic-go (1280) — своя примета.
		InitialPacketSize: 1350,
		// Как у Chrome: 100 bidi и 103 uni по умолчанию (3 uni — служебные).
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 103,
		// Дефолтные 30 с рвали бы сессию раньше, чем mux заметит обрыв.
		MaxIdleTimeout: 2 * time.Minute,
	}
}

// quicTLS — TLS-конфиг QUIC-ендпоинта: только TLS 1.3, ALPN — h3 плюс legacy.
func (s *server) quicTLS() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   alpnQUIC,
		Certificates: s.certs,
	}
}
