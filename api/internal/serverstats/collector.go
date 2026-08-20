// Package serverstats samples host resource usage from /proc and pushes it to
// the UI over the WebSocket "server_stats" channel.
//
// Design: ONE collector reads /proc once per tick and broadcasts the same
// payload to every subscriber (fan-out is the hub's job, not ours). Collection
// is gated on the subscriber count, so when no page is watching the collector
// does zero work — no /proc reads, no allocations, no broadcast.
package serverstats

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Channel is the WS channel this collector broadcasts on.
const Channel = "server_stats"

// interval between samples while there is at least one subscriber.
const interval = 2 * time.Second

// staleAfter: if the previous sample is older than this (e.g. the collector was
// idle with no subscribers), its delta would be meaningless — we re-baseline
// instead of broadcasting a bogus first value.
const staleAfter = 3 * interval

// Stats is the payload broadcast on the server_stats channel. Byte counters are
// int64; rates are bytes/sec; percentages are 0..100 floats rounded to 0.1.
type Stats struct {
	CPU      float64    `json:"cpu"`       // aggregate busy %
	Cores    []float64  `json:"cores"`     // per-core busy %
	MemPct   float64    `json:"mem_pct"`   // used memory %
	MemUsed  int64      `json:"mem_used"`  // bytes
	MemTotal int64      `json:"mem_total"` // bytes
	Net      NetRate    `json:"net"`       // bytes/sec
	Load     [3]float64 `json:"load"`      // 1m, 5m, 15m
	Cores0   int        `json:"cores_n"`   // logical CPU count
	Uptime   int64      `json:"uptime"`    // seconds since boot
	TS       int64      `json:"ts"`        // unix seconds
}

// NetRate is aggregate network throughput across non-loopback interfaces.
type NetRate struct {
	RX int64 `json:"rx"` // bytes/sec received
	TX int64 `json:"tx"` // bytes/sec transmitted
}

// cpuSample is the raw jiffie counters for one CPU line in /proc/stat.
type cpuSample struct {
	total, idle uint64
}

// Collector holds the previous sample needed to compute deltas.
type Collector struct {
	broadcast func(channel string, payload interface{})
	subCount  func(channel string) int

	prevAt   time.Time
	prevCPU  cpuSample
	prevCore []cpuSample
	prevRX   uint64
	prevTX   uint64
}

// New builds a collector. broadcast/subCount are injected (ws.Broadcast /
// ws.ChannelSubscriberCount) so this package stays free of a ws dependency and
// is trivially testable.
func New(broadcast func(string, interface{}), subCount func(string) int) *Collector {
	return &Collector{broadcast: broadcast, subCount: subCount}
}

// Run ticks forever, sampling only while the channel has subscribers. Start it
// in a goroutine: go c.Run().
func (c *Collector) Run() {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if c.subCount == nil || c.subCount(Channel) == 0 {
			// Nobody watching: forget the baseline so the next active tick
			// re-samples cleanly rather than computing a huge stale delta.
			c.prevAt = time.Time{}
			continue
		}
		if s, ok := c.sample(); ok {
			c.broadcast(Channel, s)
		}
	}
}

// sample reads /proc once and returns the computed Stats. It returns ok=false on
// the first tick (or after an idle gap), when there is no valid baseline yet to
// diff against — the caller simply skips the broadcast for that tick.
func (c *Collector) sample() (Stats, bool) {
	now := time.Now()
	fresh := !c.prevAt.IsZero() && now.Sub(c.prevAt) <= staleAfter

	aggr, cores := readCPU()
	rx, tx := readNet()

	var s Stats
	s.TS = now.Unix()
	s.Cores0 = runtime.NumCPU()
	s.MemPct, s.MemUsed, s.MemTotal = readMem()
	s.Load = readLoad()
	s.Uptime = readUptime()

	if fresh {
		s.CPU = cpuBusy(c.prevCPU, aggr)
		s.Cores = make([]float64, 0, len(cores))
		for i := range cores {
			var prev cpuSample
			if i < len(c.prevCore) {
				prev = c.prevCore[i]
			}
			s.Cores = append(s.Cores, cpuBusy(prev, cores[i]))
		}
		dt := now.Sub(c.prevAt).Seconds()
		if dt > 0 {
			s.Net = NetRate{
				RX: int64(float64(rx-c.prevRX) / dt),
				TX: int64(float64(tx-c.prevTX) / dt),
			}
		}
	}

	// Store this sample as the next baseline regardless.
	c.prevAt = now
	c.prevCPU = aggr
	c.prevCore = cores
	c.prevRX = rx
	c.prevTX = tx

	return s, fresh
}

// cpuBusy returns the busy percentage between two CPU samples, clamped 0..100.
func cpuBusy(prev, cur cpuSample) float64 {
	dt := cur.total - prev.total
	if dt == 0 {
		return 0
	}
	di := cur.idle - prev.idle
	busy := 100 * (1 - float64(di)/float64(dt))
	return round1(clamp(busy))
}

// readCPU parses /proc/stat: the aggregate "cpu" line plus each "cpuN" line.
// total = sum of all fields; idle = idle + iowait.
func readCPU() (cpuSample, []cpuSample) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, nil
	}
	defer f.Close()

	var aggr cpuSample
	var cores []cpuSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") {
			break // cpu lines are first in /proc/stat
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		var total, idle uint64
		for i, v := range fields[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
		samp := cpuSample{total: total, idle: idle}
		if fields[0] == "cpu" {
			aggr = samp
		} else {
			cores = append(cores, samp)
		}
	}
	return aggr, cores
}

// readMem parses /proc/meminfo. Used = MemTotal - MemAvailable (the figure that
// matches what tools like `free` report as actually-in-use).
func readMem() (pct float64, used, total int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	defer f.Close()

	var memTotal, memAvail int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			memTotal = kb * 1024
		case "MemAvailable:":
			memAvail = kb * 1024
		}
	}
	if memTotal <= 0 {
		return 0, 0, 0
	}
	used = memTotal - memAvail
	if used < 0 {
		used = 0
	}
	return round1(clamp(100 * float64(used) / float64(memTotal))), used, memTotal
}

// readNet sums rx/tx bytes across all interfaces except loopback and virtual
// bridges/veths (which would double-count container traffic).
func readNet() (rx, tx uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue // header lines
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "lo" || strings.HasPrefix(iface, "veth") ||
			strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "br-") {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64) // recv bytes
		t, _ := strconv.ParseUint(fields[8], 10, 64) // trans bytes
		rx += r
		tx += t
	}
	return rx, tx
}

// readLoad parses the 1/5/15-minute load averages from /proc/loadavg.
func readLoad() [3]float64 {
	var out [3]float64
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return out
	}
	fields := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(fields); i++ {
		out[i], _ = strconv.ParseFloat(fields[i], 64)
	}
	return out
}

// readUptime returns whole seconds since boot from /proc/uptime.
func readUptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(fields[0], 64)
	return int64(secs)
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
