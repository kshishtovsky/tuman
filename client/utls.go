package client

import (
	"context"
	"errors"
	"net"

	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

// hello — отпечаток ClientHello. uTLS существует ровно для одного: чтобы hello
// выглядел как браузерный, а не как Go. Поэтому профиль по умолчанию пустой и
// работает обычный crypto/tls; uTLS включается только явным выбором.
type hello struct {
	ID utls.ClientHelloID
	On bool
	// sess — тикеты сессии uTLS: свои, потому что тип состояния у пакета свой.
	sess utls.ClientSessionCache
}

// errHello — неизвестный профиль. Ошибка без адресов: NFR-11.
var errHello = errors.New("client: fingerprint: off|chrome|firefox|safari|golang")

func newHello(name string, cacheSize int) (hello, error) {
	switch name {
	case "", "off":
		return hello{}, nil
	case "chrome":
		return hello{ID: utls.HelloChrome_Auto, On: true,
			sess: utls.NewLRUClientSessionCache(cacheSize)}, nil
	case "firefox":
		return hello{ID: utls.HelloFirefox_Auto, On: true,
			sess: utls.NewLRUClientSessionCache(cacheSize)}, nil
	case "safari":
		return hello{ID: utls.HelloSafari_Auto, On: true,
			sess: utls.NewLRUClientSessionCache(cacheSize)}, nil
	case "golang":
		return hello{ID: utls.HelloGolang, On: true,
			sess: utls.NewLRUClientSessionCache(cacheSize)}, nil
	}
	return hello{}, errHello
}

// handshake ставит TLS и возвращает соединение вместе с материалом для AUTH.
// С uTLS exporter недоступен (пакет держит renegotiation включённым, а Go на
// этом отказывает), поэтому привязка идёт через AUTH v2 — сам факт проверен
// прогоном на Chrome/Firefox/Safari/Golang: hello браузерный, AUTH v2 проходит.
func (c *Client) handshake(ctx context.Context, raw net.Conn, ep Endpoint) (net.Conn, []byte, error) {
	if c.hl.On {
		u := utls.UClient(raw, &utls.Config{
			ServerName:         ep.SNI,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         ALPNList,
			InsecureSkipVerify: c.cfg.Insecure,
			ClientSessionCache: c.hl.sess,
		}, c.hl.ID)
		if err := u.HandshakeContext(ctx); err != nil {
			return nil, nil, err
		}
		return u, nil, nil
	}
	t := tls.Client(raw, &tls.Config{
		ServerName:         ep.SNI,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         ALPNList,
		InsecureSkipVerify: c.cfg.Insecure,
		// тикеты сессии: переподключение — resumption, а не полное рукопожатие
		ClientSessionCache: c.sess,
	})
	if err := t.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	state := t.ConnectionState()
	exp, err := state.ExportKeyingMaterial(AuthLabel, nil, 32)
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	return t, exp, nil
}
