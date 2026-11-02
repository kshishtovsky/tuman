package main

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/kshishtovsky/tuman/client"
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

// tunMode — мост «L3-устройство ↔ mux-поток». IP-пакеты едут одним потоком с
// FlagIP, кадрами «u16 длина + пакет»; TCP, UDP, ICMP и сборку потока делает
// стек ядра на обеих сторонах, как в WireGuard.
//
// shortcut: маршрутная таблица в TUN-режиме не применяется — что попало в
// устройство, то идёт в туннель. Разделять трафик надо маршрутами ОС; когда
// понадобится per-app или geo, фильтровать здесь по tun.Addrs(p).
type tunMode struct {
	dev  tun.Device
	pkts chan *[]byte // владение буфером переходит читателю канала
}

// startTun поднимает устройство и держит поток до остановки процесса. Ошибка
// устройства фатальна: жить без TUN, пока SOCKS работает, значит врать про
// маршрутизацию.
func (p *proxy) startTun(ctx context.Context, name, addr string) error {
	dev, err := tun.Open(name)
	if err != nil {
		return err
	}
	prefix, err := tun.PrefixOf(addr)
	if err != nil {
		dev.Close()
		return err
	}
	if err := tun.Configure(name, prefix); err != nil {
		dev.Close()
		return err
	}
	t := &tunMode{dev: dev, pkts: make(chan *[]byte, 256)}
	p.tun = t
	go t.readDevice() // одна горутина на всё время жизни: короче — утечка на каждом реконнекте
	go t.run(ctx, p.con)
	return nil
}

// readDevice читает устройство и складывает пакеты в канал; при ошибке канал
// закрывается и мост умирает вместе с устройством.
func (t *tunMode) readDevice() {
	defer close(t.pkts)
	for {
		bp := pktPool.Get().(*[]byte)
		n, err := t.dev.Read(*bp)
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
		t.pkts <- bp
	}
}

func (t *tunMode) run(ctx context.Context, c *client.Client) {
	for ctx.Err() == nil {
		st, err := c.OpenTun(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Джиттер: без него после рестарта сервера клиенты бьют синхронно.
			// Пул сам переподключается и чинит бэкграунд.
			time.Sleep(time.Second + rand.N(time.Second))
			continue
		}
		t.pump(st)
		st.Close()
	}
}

// pump гоняет пакеты в обе стороны, пока поток жив.
func (t *tunMode) pump(st *mux.Stream) {
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); t.toStream(st) }()
	go func() { defer func() { done <- struct{}{} }(); t.toDevice(st) }()
	<-done
	st.Close() // второй цикл выйдет по ошибке чтения или следующей записи
	<-done
}

// toStream — единственный писатель в поток: кадры копятся в батч и уходят одной
// записью, чтобы не делать TLS-запись на каждый пакет.
func (t *tunMode) toStream(st *mux.Stream) {
	b := tunBatch{buf: make([]byte, 0, batchMax*(2+tun.MTU))}
	for bp := range t.pkts {
		ok := b.Fill(*bp)
		*bp = (*bp)[:cap(*bp)] // вернуть полную длину: Read пишет во весь буфер
		pktPool.Put(bp)        // только после copy в батч и в этой же горутине
		if !ok {
			continue // больше MTU устройство не отдаёт; мост на таком не падает
		}
		if b.Full() {
			if err := b.Flush(st); err != nil {
				return
			}
			continue
		}
		// Канал пуст — копить больше нечего, иначе пакет пролежит до следующего.
		if len(t.pkts) == 0 {
			if err := b.Flush(st); err != nil {
				return
			}
		}
	}
	b.Flush(st) // канал закрыт: остаток обязан уйти в поток
}

func (t *tunMode) toDevice(st *mux.Stream) {
	buf := make([]byte, tun.MTU)
	for {
		var h [2]byte
		if _, err := io.ReadFull(st, h[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n == 0 || n > len(buf) {
			return // нарушение формата: рвём мост, сессию не трогаем
		}
		if _, err := io.ReadFull(st, buf[:n]); err != nil {
			return
		}
		if _, err := t.dev.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (t *tunMode) Close() error { return t.dev.Close() }
