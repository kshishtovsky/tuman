package client

import "testing"

// New пересобирает ендпоинты, и однажды это уже теряло QUIC: клиент молча
// уезжал по TCP, а замеры «QUIC» оказывались замерами TCP.
func TestNewKeepsQUIC(t *testing.T) {
	c, err := New(Config{
		Servers: []Endpoint{{Addr: "127.0.0.1:18443", SNI: "a.example", QUIC: true}},
		PSK:     make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.eps[0].QUIC {
		t.Fatal("QUIC потерян при пересборке ендпоинтов")
	}
}

// Регресс: "tuman" в клиентском ALPN — постоянная метка для middlebox, который
// видел Initial один раз. Клиент обязан выглядеть как браузер: только h3.
func TestQUICALPNLooksLikeH3(t *testing.T) {
	if ALPNQUIC != "h3" {
		t.Fatalf("клиентский ALPN %q, ожидался только h3", ALPNQUIC)
	}
}
