package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohSrv — фейковый DoH-сервер: отвечает A и AAAA на любое имя и считает запросы.
func dohSrv(t *testing.T, a [4]byte, cname bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			t.Errorf("content-type %q", ct)
		}
		var p dnsmessage.Parser
		h, err := p.Start(body)
		if err != nil {
			t.Errorf("parse query: %v", err)
			return
		}
		q, err := p.Question()
		if err != nil {
			t.Errorf("question: %v", err)
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
		b.EnableCompression()
		if err := b.StartQuestions(); err != nil {
			t.Error(err)
			return
		}
		if err := b.Question(q); err != nil {
			t.Error(err)
			return
		}
		if err := b.StartAnswers(); err != nil {
			t.Error(err)
			return
		}
		// CNAME перед адресом: проверяем, что парсер не останавливается на нём.
		if cname {
			n, _ := dnsmessage.NewName("edge.example.test.")
			if err := b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME,
				Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.CNAMEResource{CNAME: n}); err != nil {
				t.Error(err)
				return
			}
		}
		switch q.Type {
		case dnsmessage.TypeA:
			err = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA,
				Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.AResource{A: a})
		case dnsmessage.TypeAAAA:
			err = b.AAAAResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0xd, 0xb8}})
		}
		if err != nil {
			t.Error(err)
			return
		}
		out, err := b.Finish()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func newTestDOH(t *testing.T, srv *httptest.Server) *doh {
	t.Helper()
	d, err := newDOH(srv.URL)
	if err != nil {
		t.Fatalf("newDOH: %v", err)
	}
	d.hc = srv.Client() // доверяем тестовому серту
	return d
}

func TestDOHLookup(t *testing.T) {
	srv, _ := dohSrv(t, [4]byte{93, 184, 216, 34}, true)
	d := newTestDOH(t, srv)

	ips, err := d.lookup(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	var has4, has6 bool
	for _, ip := range ips {
		has4 = has4 || ip.Is4()
		has6 = has6 || ip.Is6()
	}
	if !has4 || !has6 {
		t.Fatalf("адреса %v: нужны и A, и AAAA", ips)
	}
	// AAAA приходит раньше A, но первым адресом обязан быть IPv4.
	if !ips[0].Is4() {
		t.Fatalf("первым идёт %v — IPv6 на VPS без v6 недостижим", ips[0])
	}
	if ips[0].String() != "93.184.216.34" {
		t.Fatalf("A-запись потерялась: %v", ips)
	}
	// TTL берётся минимальный из двух ответов (A=120, AAAA=60), но не меньше ttlMin.
	if e := d.c["example.test"]; e.exp.Sub(time.Now()) > ttlMin+2*time.Second {
		t.Fatalf("кеш живёт %v — TTL не учтён", e.exp.Sub(time.Now()))
	}
}

// Второй запрос того же имени не должен идти в сеть: иначе каждый новый сокет
// платит два HTTPS-RTT.
func TestDOHCache(t *testing.T) {
	srv, n := dohSrv(t, [4]byte{1, 2, 3, 4}, false)
	d := newTestDOH(t, srv)

	for range 5 {
		if _, err := d.lookup(context.Background(), "cache.test"); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if got := n.Load(); got != 2 {
		t.Fatalf("запросов к DoH: %d, ждали 2 (A+AAAA один раз)", got)
	}
}

func TestDOHIPLiteral(t *testing.T) {
	srv, n := dohSrv(t, [4]byte{1, 2, 3, 4}, false)
	d := newTestDOH(t, srv)

	ips, err := d.lookup(context.Background(), "192.0.2.7")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatalf("IP-литерал: %v %v", ips, err)
	}
	if v6 := net.ParseIP("2001:db8::1"); v6 != nil {
		if ips, err := d.lookup(context.Background(), "2001:db8::1"); err != nil || len(ips) != 1 {
			t.Fatalf("IPv6-литерал: %v %v", ips, err)
		}
	}
	if n.Load() != 0 {
		t.Fatalf("IP-литерал ушёл в DoH: %d запросов", n.Load())
	}
}

// Ошибка резолва не должна подменяться системным резолвером молча: иначе
// провайдер снова видит имена, а оператор уверен, что включён DoH.
func TestDOHFailureIsHard(t *testing.T) {
	srv, _ := dohSrv(t, [4]byte{1, 2, 3, 4}, false)
	d := newTestDOH(t, srv)
	d.url = srv.URL // сервер уже закрыт для новых соединений?
	srv.Close()

	if _, err := d.lookup(context.Background(), "dead.test"); err == nil {
		t.Fatal("резолв через закрытый DoH вернул успех")
	}
}

// Egress берёт адрес из резолвера, а не из системного DNS.
func TestDialTargetUsesDOH(t *testing.T) {
	srv, _ := dohSrv(t, [4]byte{10, 1, 2, 3}, false)
	s := &server{dns: newTestDOH(t, srv)}

	got, err := s.dialTarget(context.Background(), "target.test", "8443")
	if err != nil {
		t.Fatalf("dialTarget: %v", err)
	}
	if got != "10.1.2.3:8443" {
		t.Fatalf("адрес %q, ждали 10.1.2.3:8443", got)
	}
	// без резолвера — прежнее поведение
	s2 := &server{}
	if got, err := s2.dialTarget(context.Background(), "target.test", "443"); err != nil || got != "target.test:443" {
		t.Fatalf("без dns: %q %v", got, err)
	}
}

func TestDOHBadURL(t *testing.T) {
	for _, u := range []string{"1.1.1.1/dns-query", "http://1.1.1.1/dns-query", "https://"} {
		if _, err := newDOH(u); err == nil {
			t.Fatalf("newDOH(%q) принял негодный адрес", u)
		}
	}
}
