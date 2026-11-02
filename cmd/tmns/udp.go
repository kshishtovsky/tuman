package main

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// maxDatagram — потолок полезной нагрузки одной датаграммы. 65507 — максимум
// UDP поверх IPv4, но mux несёт длину в 2 байтах, а память на поток дешевле
// отдать под потоковую передачу: 8 КиБ покрывает DNS, QUIC и голос.
const maxDatagram = 8 << 10

// udpIdle — сколько ждём датаграмм, прежде чем закрыть поток: ассоциация SOCKS
// живёт, пока живёт TCP-контроль, но сервер об этом не знает и не должен
// держать сокет вечно.
const udpIdle = 60 * time.Second

// relayUDP — поток-датаграммы: каждая запись в потоке это u16 длина + полезная
// нагрузка. Цель диалеится так же, как у TCP: тот же egress-фильтр и тот же
// резолвер, иначе UDP стал бы дырой в SSRF-защите.
func (s *server) relayUDP(st *mux.Stream) {
	host, port, err := proto.DecodeTarget(st.Target())
	if err != nil {
		st.Close()
		s.log.Debug("egress", "err", "bad_target")
		return
	}
	addr, err := s.dialTarget(s.ctx, host, port)
	if err != nil {
		st.Close()
		s.log.Debug("egress", "err", "dns")
		return
	}
	// Тот же фильтр, что у TCP: иначе UDP стал бы обходом SSRF-защиты.
	if err := egressAllowed("udp", addr, s.allowPrivate); err != nil {
		st.Close()
		s.log.Debug("egress", "err", "egress_denied")
		return
	}
	up, err := net.Dial("udp", addr)
	if err != nil {
		st.Close()
		s.log.Debug("egress", "err", errKind(err))
		return
	}
	defer up.Close()

	var wmu sync.Mutex // две горутины пишут в поток
	write := func(p []byte) error {
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(p)))
		wmu.Lock()
		defer wmu.Unlock()
		if _, err := st.Write(h[:]); err != nil {
			return err
		}
		_, err := st.Write(p)
		return err
	}

	done := make(chan struct{}, 2)
	go func() { // клиент → цель
		defer func() { done <- struct{}{} }()
		buf := make([]byte, maxDatagram)
		for {
			st.SetReadDeadline(time.Now().Add(udpIdle))
			var h [2]byte
			if _, err := io.ReadFull(st, h[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(h[:]))
			if n == 0 || n > maxDatagram {
				return // нарушение формата: рвём поток, не сессию
			}
			if _, err := io.ReadFull(st, buf[:n]); err != nil {
				return
			}
			if _, err := up.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	go func() { // цель → клиент
		defer func() { done <- struct{}{} }()
		buf := make([]byte, maxDatagram)
		for {
			up.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			if err := write(buf[:n]); err != nil {
				return
			}
		}
	}()
	<-done
	st.Close() // вторая горутина выйдет по ошибке чтения/записи
	<-done
}
