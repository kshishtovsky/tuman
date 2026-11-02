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
