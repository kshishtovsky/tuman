package client

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/kshishtovsky/tuman/mux"
)

// ALPNQUIC — как у настоящего HTTP/3-клиента: только h3. h3-29 браузеры сняли
// ещё в 2022 (Chrome перешёл на финальный RFC 9114), так что draft-имя в
// ClientHello само по себе выделяло бы нас; своё "tuman" — вечная метка для
// middlebox: увидел один Initial и запомнил весь трафик.
const ALPNQUIC = "h3"

// shortcut: шейпер (profile) на QUIC-путь не навешен — он паддит записи
// TLS, а у QUIC своё паддинг-поведение; включать, если профиль понадобится.
//
// dialQUIC поднимает одну сессию по QUIC. TLS 1.3 живёт внутри QUIC, поэтому
// второй TLS не делается: mux идёт прямо в потоке, а привязка к каналу —
// AUTH v2 (X25519), который exporter не требует.
func (c *Client) dialQUIC(ctx context.Context, ep Endpoint) (*mux.Session, error) {
	// Несоединённый сокет: quic-go пишет через WriteTo, а на pre-connected
	// UDP Go отвечает «use of WriteTo with pre-connected connection» — с
	// Dialer.DialContext QUIC не поднимался вообще. Control берём у
	// protect-диалера Android, иначе QUIC уйдёт мимо туннеля.
	lc := net.ListenConfig{Control: c.cfg.Dialer.Control}
	pc, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	ua, err := net.ResolveUDPAddr("udp", ep.Addr)
	if err != nil {
		pc.Close()
		return nil, err
	}
	conn, err := quic.Dial(ctx, pc, ua, &tls.Config{
		ServerName:         ep.SNI,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNQUIC},
		InsecureSkipVerify: c.cfg.Insecure,
		ClientSessionCache: c.sess,
	}, quicConf())
	if err != nil {
		pc.Close()
		return nil, err
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	// Поток живёт, пока жива сессия: mux.Close зовёт Close ниже и заодно
	// закрывает QUIC-соединение — иначе сокет и горутины quic-go утекают.
	s, err := mux.New(&quicCarrier{Stream: st, conn: conn},
		mux.Config{IsClient: true, PSK: c.cfg.PSK, AuthV2: true,
			PingEvery: c.cfg.PingEvery, PingMiss: c.cfg.PingMiss})
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	return s, nil
}

// quicConf: транспортные параметры под браузер.
func quicConf() *quic.Config {
	return &quic.Config{
		// Браузеры паддят Initial до 1350 Б; дефолт quic-go (1280) — своя примета.
		InitialPacketSize: 1350,
		// Как у Chrome: 100 bidi и 103 uni по умолчанию (3 uni — служебные).
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 103,
		// mux пингует каждые 25 с, а дефолтные 30 с idle рвали бы соединение
		// раньше, чем mux заметит: выглядело бы как потеря сессии без причины.
		MaxIdleTimeout:  2 * time.Minute,
		KeepAlivePeriod: 0, // keepalive — забота mux, дублировать не нужно
	}
}

// quicCarrier — QUIC-поток как io.ReadWriter для mux. Close закрывает и
// соединение: одна сессия = одно QUIC-соединение.
type quicCarrier struct {
	*quic.Stream
	conn *quic.Conn
}

func (q *quicCarrier) Close() error {
	err := q.Stream.Close()
	q.conn.CloseWithError(0, "")
	return err
}
