package openwrt

import (
	"context"
	"testing"
	"time"
)

type scriptedRunner struct {
	output string
}

func (r scriptedRunner) Run(context.Context, string) (string, error) { return r.output, nil }
func (r scriptedRunner) RunInput(context.Context, string, []byte) (string, error) {
	return r.output, nil
}
func (r scriptedRunner) Close() error { return nil }

func newTestClient(runner Runner) *Client {
	return New(runner, time.Second, "/tmp/dhcp.leases", "/proc/net/nf_conntrack", 100, "/etc/sing-box/config.json", "")
}

func TestInterfaceCountersParsesBytes(t *testing.T) {
	client := newTestClient(scriptedRunner{output: "12345\n6789\n"})

	rx, tx, err := client.InterfaceCounters(context.Background(), "wan")
	if err != nil {
		t.Fatal(err)
	}
	if rx != 12345 || tx != 6789 {
		t.Fatalf("unexpected counters: rx=%d tx=%d", rx, tx)
	}
}

func TestInterfaceCountersRejectsEmptyInterface(t *testing.T) {
	client := newTestClient(scriptedRunner{output: ""})
	if _, _, err := client.InterfaceCounters(context.Background(), "  "); err == nil {
		t.Fatal("expected error for empty interface name")
	}
}

func TestSystemInfoParsesProcFiles(t *testing.T) {
	output := "12345.67 8901.23\n---\n0.42 0.30 0.25 1/123 4567\n---\n" +
		"MemTotal:        1024000 kB\nMemAvailable:     256000 kB\n"
	client := newTestClient(scriptedRunner{output: output})

	info, err := client.SystemInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.UptimeSeconds != 12345.67 {
		t.Fatalf("unexpected uptime: %v", info.UptimeSeconds)
	}
	if info.LoadAvg1 != 0.42 {
		t.Fatalf("unexpected load avg: %v", info.LoadAvg1)
	}
	if info.MemTotalKB != 1024000 || info.MemAvailableKB != 256000 {
		t.Fatalf("unexpected mem: total=%d available=%d", info.MemTotalKB, info.MemAvailableKB)
	}
}
