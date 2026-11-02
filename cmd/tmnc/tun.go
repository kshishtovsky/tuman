package main

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/kshishtovsky/tuman/client"
	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/tun"
)

// tunMode — мост «L3-устройство ↔ mux-поток». IP-пакеты едут одним потоком с
// FlagIP, кадрами «u16 длина + пакет»; TCP, UDP, ICMP и сборку потока делает
// стек ядра на обеих сторонах, как в WireGuard.
//
// shortcut: маршрутная таблица в TUN-режиме не применяется — что попало в
// устройство, то идёт в туннель. Разделять трафик надо маршрутами ОС; когда
// понадобится per-app или geo, фильтровать здесь по tun.Addrs(p).
type tunMode struct {
	dev  tun.Device
	pkts chan []byte
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
	t := &tunMode{dev: dev, pkts: make(chan []byte, 256)}
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
		buf := make([]byte, tun.MTU)
		n, err := t.dev.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		// Блокирующая запись = backpressure: медленный поток тормозит чтение
		// устройства, а буфером служит кольцо драйвера на 4 МиБ. Со drop под
		// нагрузкой терялось 97 % пакетов.
		t.pkts <- buf[:n]
	}
}

func (t *tunMode) run(ctx context.Context, c *client.Client) {
	for ctx.Err() == nil {
		st, err := c.OpenTun(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Second) // пул сам переподключается и чинит бэкграунд
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

// toStream — единственный писатель в поток: кадр целиком, чтобы получатель не
// собирал длину и тело из разных горутин.
func (t *tunMode) toStream(st *mux.Stream) {
	var frame [2 + tun.MTU]byte
	for {
		select {
		case p, ok := <-t.pkts:
			if !ok {
				return
			}
			binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
			n := copy(frame[2:], p)
			if _, err := st.Write(frame[:2+n]); err != nil {
				return
			}
		}
	}
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
