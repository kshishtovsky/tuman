package main

// UDP path probe: usink <port> [secs] | ublast <host:port> <secs> <Mbit>
import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func usink(port string, secs int) {
	pc, err := net.ListenPacket("udp", ":"+port)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 2048)
	var total, pkts int64
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	pc.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		total += int64(n)
		pkts++
	}
	fmt.Printf("UDP received %.1f MB in %ds = %.1f Mbit/s (%d pkts, avg %d B)\n",
		float64(total)/1e6, secs, float64(total)*8/float64(secs)/1e6, pkts, total/max64(pkts, 1))
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func ublast(addr string, secs int, mbit int) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		panic(err)
	}
	payload := make([]byte, 1200)
	// pace: mbit/8 bytes per second, in 1ms ticks
	perTick := mbit * 125 // bytes per ms (= mbit*1e6/8/1000)
	if perTick < 1200 {
		perTick = 1200
	}
	var sent int64
	start := time.Now()
	end := start.Add(time.Duration(secs) * time.Second)
	tick := time.NewTicker(time.Millisecond)
	for time.Now().Before(end) {
		<-tick.C
		for b := 0; b < perTick; b += 1200 {
			n, err := c.Write(payload)
			if err != nil {
				break
			}
			sent += int64(n)
		}
	}
	sec := time.Since(start).Seconds()
	fmt.Printf("UDP sent %.1f MB in %.1fs = %.1f Mbit/s (target %d Mbit/s)\n",
		float64(sent)/1e6, sec, float64(sent)*8/sec/1e6, mbit)
}

func main() {
	switch os.Args[1] {
	case "usink":
		s, _ := strconv.Atoi(os.Args[3])
		usink(os.Args[2], s)
	case "ublast":
		s, _ := strconv.Atoi(os.Args[3])
		m, _ := strconv.Atoi(os.Args[4])
		ublast(os.Args[2], s, m)
	}
}
