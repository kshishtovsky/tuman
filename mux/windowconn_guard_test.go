package mux_test

// Регресс на мину, найденную аудитом: AUTH_OK v2 не несёт лимитов (кадр
// фиксированной длины, менять раскладку нельзя — уже выпущенные клиенты другой
// длины не примут, а rupas пиннит tuman v0.3.1). Значит v2-клиент всегда
// считает окно соединения дефолтным, и сервер с уменьшенным окном порвал бы
// сессию ErrProtocol на первом всплеске. Теперь такой сервер не стартует.

import (
	"errors"
	"net"
	"testing"

	"github.com/kshishtovsky/tuman/mux"
)

func TestV2RejectsNonDefaultWindowConn(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	// Сервер, v2, окно 4 МиБ: раньше это «работало» до первого всплеска.
	_, err := mux.New(nil, mux.Config{PSK: psk, AuthV2: true, WindowConn: 4 << 20})
	if !errors.Is(err, mux.ErrWindowConnV2) {
		t.Fatalf("ждали ErrWindowConnV2, получили %v", err)
	}
	// v1 — окно доезжает в AUTH_OK, настройка законна (пайп пуст, поэтому
	// дальше handshake падает: важно лишь, что не ErrWindowConnV2).
	if err := newWith(t, mux.Config{PSK: psk, Exporter: psk, WindowConn: 4 << 20}); errors.Is(err, mux.ErrWindowConnV2) {
		t.Fatalf("v1 не должен получать ErrWindowConnV2: %v", err)
	}
	// Клиент — своё окно отправки, протокол тут ни при чём.
	if err := newWith(t, mux.Config{IsClient: true, PSK: psk, AuthV2: true, WindowConn: 4 << 20}); errors.Is(err, mux.ErrWindowConnV2) {
		t.Fatalf("клиент не должен получать ErrWindowConnV2: %v", err)
	}
}

// newWith создаёт сессию поверх закрытого пайпа и возвращает ошибку New.
func newWith(t *testing.T, cfg mux.Config) error {
	t.Helper()
	a, b := net.Pipe()
	b.Close()
	defer a.Close()
	_, err := mux.New(a, cfg)
	return err
}
