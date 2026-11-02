package client

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/kshishtovsky/tuman/mux"
)

// ALPNQUIC — единственный протокол QUIC-ендпоинта. Отдельный от h2/http1.1:
// чужой QUIC-клиент (браузер) на этот порт не доедет и получит отказ на ALPN,
// а не увидит наш туннель.
const ALPNQUIC = "tuman"

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

// quicConf: our mux сам пингует каждые 25 с, поэтому idle-таймаут QUIC должен
// быть заметно больше — иначе QUIC закроет соединение раньше, чем mux успеет
// заметить, и это будет выглядеть как потеря сессии без причины.
func quicConf() *quic.Config {
	return &quic.Config{
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
