package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

// Метрики — единственный способ узнать объёмы: сервер больше нигде их не
// хранит. Тест держит контракт имён (по ним строятся графики) и то, что
// счётчики действительно растут.
func TestStatsEndpointReportsCounters(t *testing.T) {
	s := &server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.nTunnel.Store(7)
	s.nQUIC.Store(2)
	s.st.bytesUp.Add(1024)
	s.st.bytesDown.Add(2048)
	s.st.dgramIn.Add(3)
	s.st.egressDenied.Add(1)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	s.metrics(w, req)

	body, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tmn_tunnel_sessions_total 7",
		"tmn_quic_sessions_total 2",
		"tmn_bytes_up_total 1024",
		"tmn_bytes_down_total 2048",
		"tmn_udp_datagrams_in 3",
		"tmn_egress_denied_total 1",
		"tmn_conns_active 0",
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("в /metrics нет %q:\n%s", want, body)
		}
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type %q", ct)
	}

	w = httptest.NewRecorder()
	s.statsJSON(w, httptest.NewRequest("GET", "/stats", nil))
	var got map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["bytes_up_total"] != 1024 {
		t.Fatalf("json: %v", got)
	}
}

func TestStatAddr(t *testing.T) {
	for in, want := range map[string]string{
		"":                "",
		"off":             "",
		"9090":            "127.0.0.1:9090",
		"127.0.0.1:9090":  "127.0.0.1:9090",
		"[::1]:9090":      "[::1]:9090",
		"999999":          "999999",
		"не адрес вообще": "не адрес вообще",
	} {
		if got := statAddr(in); got != want {
			t.Fatalf("statAddr(%q) = %q, ждали %q", in, got, want)
		}
	}
}
