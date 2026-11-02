package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// stats — то, чего у tmns не было вообще: раньше объёмы, число сессий и
// отказы egress существовали только как строки в логах, и на вопрос «сколько
// через сервер прошло за сутки» ответить было нечем. Счётчики живут на
// сервере, отдаются в текстовом формате Prometheus и в JSON.
//
// Стоимость: один atomic.Add на скопированный буфер (32 КиБ) и на датаграмму,
// то есть на горячем пути остаётся ноль аллокаций.
type stats struct {
	bytesUp, bytesDown atomic.Int64
	dgramIn, dgramOut  atomic.Int64
	streams            atomic.Int64 // активные TCP-потоки
	udpAssoc           atomic.Int64 // активные UDP-ассоциации
	egressDenied       atomic.Int64
	badTarget          atomic.Int64
	dnsFail            atomic.Int64
	eofs               atomic.Int64 // сессии, оборванные на полуслове
}

// snapshot собирается раз на запрос: чтение счётчиков и активные соединения.
func (s *server) snapshot() map[string]int64 {
	st := &s.st
	m := map[string]int64{
		"tunnel_sessions_total": s.nTunnel.Load(),
		"cover_requests_total":  s.nCover.Load(),
		"quic_sessions_total":   s.nQUIC.Load(),
		"streams_active":        st.streams.Load(),
		"udp_assoc_active":      st.udpAssoc.Load(),
		"bytes_up_total":        st.bytesUp.Load(),
		"bytes_down_total":      st.bytesDown.Load(),
		"udp_datagrams_in":      st.dgramIn.Load(),
		"udp_datagrams_out":     st.dgramOut.Load(),
		"egress_denied_total":   st.egressDenied.Load(),
		"bad_target_total":      st.badTarget.Load(),
		"dns_fail_total":        st.dnsFail.Load(),
	}
	s.mu.Lock()
	m["conns_active"] = int64(len(s.conns))
	s.mu.Unlock()
	return m
}

// serveStats — отдельный listener только для мониторинга. Он никогда не
// делит адрес с прикрытием: у прикрытия любой лишний путь виден DPI, а
// метрики должны читаться с localhost или из ssh-туннеля.
func (s *server) serveStats(addr string, lg *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		for k, v := range s.snapshot() {
			fmt.Fprintf(w, "tmn_%s %d\n", k, v)
		}
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.snapshot())
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		lg.Error("stats: слушатель не поднялся", "addr", addr, "err", err)
		return
	}
	lg.Info("stats", "addr", addr)
	go func() {
		<-s.ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		lg.Error("stats: остановлен", "err", err)
	}
}

// metrics — текстовый формат Prometheus: имена стабильные, по ним строятся
// графики; сортировки нет намеренно (порядок строк для скрейпера не значит
// ничего, а лишний sort — аллокации на каждый запрос).
func (s *server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	for k, v := range s.snapshot() {
		fmt.Fprintf(w, "tmn_%s %d\n", k, v)
	}
}

func (s *server) statsJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.snapshot())
}

// statAddr разбирает stats_listen: пусто — выключено, «off» — тоже.
func statAddr(v string) string {
	switch v {
	case "", "off", "none", "-":
		return ""
	}
	if _, _, err := net.SplitHostPort(v); err != nil {
		// Голый порт («9090») трактуем как localhost:9090.
		if n, cErr := strconv.Atoi(v); cErr == nil && n > 0 && n < 65536 {
			return "127.0.0.1:" + v
		}
	}
	return v
}
