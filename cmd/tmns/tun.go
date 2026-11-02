package main

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/tun"
)

// pktPool — буферы чтения устройства: на 1 Гбит/с без пула это ~9000 make()/с
// и GC каждые несколько секунд. В пуле указатель, а не срез: sync.Pool с срезом
// аллоцирует заголовок среза на каждом Put, и пул перестаёт экономить.
var pktPool = sync.Pool{New: func() any { b := make([]byte, tun.MTU); return &b }}

// batchMax — кадров в одной записи потока: 8 syscall'ов превращаются в один,
// а задержку батч не добавляет (на пустом канале сбрасывается сразу).
const batchMax = 8

// tunBatch копит кадры «u16 длина + пакет» и сбрасывает их одним Write. Провод
// от этого не меняется: получатель читает 2+len в цикле, поток байтовый, и N
// кадров в одной записи для него неотличимы от N записей.
type tunBatch struct {
	buf []byte
	n   int // кадров в батче
}

// Fill добавляет пакет в батч; false — пакет больше MTU, батч не тронут.
func (b *tunBatch) Fill(p []byte) bool {
	if len(p) > tun.MTU {
		return false
	}
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(len(p)))
	b.buf = append(b.buf, p...)
	b.n++
	return true
}

// Full — набралось batchMax кадров, пора слать.
func (b *tunBatch) Full() bool { return b.n >= batchMax }

// Flush отдаёт накопленное одним Write; пустой батч не пишет ничего.
func (b *tunBatch) Flush(w io.Writer) error {
	if b.n == 0 {
		return nil
	}
	buf := b.buf
	b.buf, b.n = b.buf[:0], 0
	_, err := w.Write(buf)
	return err
}

// tunBridge — серверная половина режима TUN: поток IP-пакетов ↔ устройство.
// Устройство одно на процесс, поэтому поток-владелец один; второй клиент
// получит отказ, а не половину пакетов.
type tunBridge struct {
	dev  tun.Device
	pkts chan *[]byte // из устройства в поток-владелец; владение буфером — у читателя

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
	b := &tunBridge{dev: dev, pkts: make(chan *[]byte, 256)}
	s.tun = b
	go b.readDevice()
	return nil
}

func (b *tunBridge) readDevice() {
	defer close(b.pkts)
	for {
		bp := pktPool.Get().(*[]byte)
		n, err := b.dev.Read(*bp)
		if err != nil {
			pktPool.Put(bp)
			return
		}
		if n == 0 {
			pktPool.Put(bp)
			continue
		}
		*bp = (*bp)[:n]
		// Блокирующая запись = backpressure: медленный поток тормозит чтение
		// устройства, а буфером служит кольцо драйвера на 4 МиБ. Со drop под
		// нагрузкой терялось 97 % пакетов.
		b.pkts <- bp
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

// toStream — единственный писатель в поток: кадры копятся в батч и уходят одной
// записью, чтобы не делать TLS-запись на каждый пакет.
func (b *tunBridge) toStream(st *mux.Stream) {
	batch := tunBatch{buf: make([]byte, 0, batchMax*(2+tun.MTU))}
	for bp := range b.pkts {
		ok := batch.Fill(*bp)
		*bp = (*bp)[:cap(*bp)] // вернуть полную длину: Read пишет во весь буфер
		pktPool.Put(bp)        // только после copy в батч и в этой же горутине
		if !ok {
			continue // больше MTU устройство не отдаёт; мост на таком не падает
		}
		if batch.Full() {
			if err := batch.Flush(st); err != nil {
				return
			}
			continue
		}
		// Канал пуст — копить больше нечего, иначе пакет пролежит до следующего.
		if len(b.pkts) == 0 {
			if err := batch.Flush(st); err != nil {
				return
			}
		}
	}
	batch.Flush(st) // канал закрыт: остаток обязан уйти в поток
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
