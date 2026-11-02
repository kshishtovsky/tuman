package mux_test

import (
	"context"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
)

// Поток IP-пакетов открывается без адресного блока: пустой payload не должен
// ждать кредит окна (регресс: reserve с max=0 висел вечно).
func TestOpenEmptyPayload(t *testing.T) {
	a, b := pair(t)
	done := make(chan *mux.Stream, 1)
	go func() {
		st, err := a.OpenTun(context.Background())
		if err != nil {
			t.Errorf("OpenTun: %v", err)
			done <- nil
			return
		}
		done <- st
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := b.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("пир не принял пустой OPEN: %v", err)
	}
	if !peer.IsIP() {
		t.Fatal("пир не увидел FlagIP")
	}
	if len(peer.Target()) != 0 {
		t.Fatalf("у IP-потока появился адресный блок: %x", peer.Target())
	}
	if st := <-done; st == nil {
		t.Fatal("OpenTun не открылся")
	}
}
