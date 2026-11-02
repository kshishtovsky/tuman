package main

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/tun"
)

// tunBridge — серверная половина режима TUN: поток IP-пакетов ↔ устройство.
// Устройство одно на процесс, поэтому поток-владелец один; второй клиен­т
// получит отказ, а не половину пакетов.
type tunBridge struct {
	dev  tun.Device
	pkts chan []byte // из устройства в поток-владелец

	mu    sync.Mutex
	owner *mux.Stream
}

func (s *server) startTun() error {
	dev, err := tun.Open(s.cfg.Tun)
	if err != nil {
		return err
	}
	prefix, err := tun.PrefixOf(s.cfg.TunAddr)
	if err != nil {
		dev.Close()
		return err
	}
	if err := tun.Configure(s.cfg.Tun, prefix); err != nil {
		dev.Close()
		return err
	}
	b := &tunBridge{dev: dev, pkts: make(chan []byte, 256)}
	s.tun = b
	go b.readDevice()
	return nil
}

func (b *tunBridge) readDevice() {
	defer close(b.pkts)
	for {
		buf := make([]byte, tun.MTU)
		n, err := b.dev.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		// Блокирующая запись = backpressure: медленный поток тормозит чтение
		// устройства, а буфером служит кольцо драйвера на 4 МиБ. Со drop под
		// нагрузкой терялось 97 % пакетов.
		b.pkts <- buf[:n]
	}
}

// serveIP — поток IP-пакетов от клиента. Владелец устройства один: иначе два
// клиента делят одно кольцо и теряют пакеты друг друга.
func (s *server) serveIP(st *mux.Stream) {
	b := s.tun
	b.mu.Lock()
	if b.owner != nil {
		b.mu.Unlock()
		s.log.Debug("tun", "err", "busy")
		st.Close()
		return
	}
	b.owner = st
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.owner = nil
		b.mu.Unlock()
		st.Close()
	}()

	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); b.toStream(st) }()
	go func() { defer func() { done <- struct{}{} }(); b.toDevice(st) }()
	<-done
	st.Close()
	<-done
}

func (b *tunBridge) toStream(st *mux.Stream) {
	var frame [2 + tun.MTU]byte
	for p := range b.pkts {
		binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
		n := copy(frame[2:], p)
		if _, err := st.Write(frame[:2+n]); err != nil {
			return
		}
	}
}

func (b *tunBridge) toDevice(st *mux.Stream) {
	buf := make([]byte, tun.MTU)
	for {
		var h [2]byte
		if _, err := io.ReadFull(st, h[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n == 0 || n > len(buf) {
			return // нарушение формата: рвём поток, сессию не трогаем
		}
		if _, err := io.ReadFull(st, buf[:n]); err != nil {
			return
		}
		if _, err := b.dev.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (b *tunBridge) Close() error { return b.dev.Close() }
