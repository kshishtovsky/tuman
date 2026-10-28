package main

// Raw channel bench: sink (server) + push/pull (client).
// usage: bench3 sink <port> | bench3 push <host:port> <MB>
import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

func sink(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sink listening :%s\n", port)
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			start := time.Now()
			n, _ := io.Copy(io.Discard, c)
			sec := time.Since(start).Seconds()
			fmt.Printf("recv %.1f MB in %.2fs = %.1f MB/s (%.0f Mbit/s) from %s\n",
				float64(n)/1e6, sec, float64(n)/sec/1e6, float64(n)*8/sec/1e6, c.RemoteAddr())
		}(c)
	}
}

func serve(port, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}
	fmt.Printf("serve %s on :%s (%d MB)\n", path, port, len(data)>>20)
	var mu sync.Mutex
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			n, _ := c.Write(data)
			mu.Lock()
			fmt.Printf("sent %.1f MB to %s\n", float64(n)/1e6, c.RemoteAddr())
			mu.Unlock()
		}(c)
	}
}

func get(addr string, mb int64) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	start := time.Now()
	n, err := io.CopyN(io.Discard, c, mb<<20)
	sec := time.Since(start).Seconds()
	if err != nil {
		fmt.Printf("get ended early: %v\n", err)
	}
	fmt.Printf("got %.1f MB in %.2fs = %.1f MB/s (%.0f Mbit/s)\n", float64(n)/1e6, sec, float64(n)/sec/1e6, float64(n)*8/sec/1e6)
}

func push(addr string, mb int64) {
	buf := make([]byte, 1<<20)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	start := time.Now()
	var sent int64
	for sent < mb<<20 {
		n, err := c.Write(buf)
		if err != nil {
			break
		}
		sent += int64(n)
	}
	sec := time.Since(start).Seconds()
	fmt.Printf("sent %.1f MB in %.2fs = %.1f MB/s (%.0f Mbit/s)\n", float64(sent)/1e6, sec, float64(sent)/sec/1e6, float64(sent)*8/sec/1e6)
	c.Close()
}

func pull(addr string, mb int64) {
	start := time.Now()
	resp, err := http.Get("http://" + addr + "/t200.bin")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	sec := time.Since(start).Seconds()
	fmt.Printf("pulled %.1f MB in %.2fs = %.1f MB/s (%.0f Mbit/s)\n", float64(n)/1e6, sec, float64(n)/sec/1e6, float64(n)*8/sec/1e6)
}

func main() {
	switch os.Args[1] {
	case "sink":
		sink(os.Args[2])
	case "serve":
		serve(os.Args[2], os.Args[3])
	case "get":
		v, _ := strconv.ParseInt(os.Args[3], 10, 64)
		get(os.Args[2], v)
	case "push":
		v, _ := strconv.ParseInt(os.Args[3], 10, 64)
		push(os.Args[2], v)
	case "pull":
		v, _ := strconv.ParseInt(os.Args[3], 10, 64)
		pull(os.Args[2], v)
	}
}
