package service

import (
	"context"
	"testing"
	"time"

	"openwrt-parser-go/internal/openwrt"
)

type stepCounterRunner struct {
	calls int
	steps []string
}

func (r *stepCounterRunner) Run(context.Context, string) (string, error) {
	out := r.steps[r.calls]
	if r.calls < len(r.steps)-1 {
		r.calls++
	}
	return out, nil
}

func (r *stepCounterRunner) RunInput(context.Context, string, []byte) (string, error) {
	return "", nil
}

func (r *stepCounterRunner) Close() error { return nil }

func TestCollectServiceSampleThroughputComputesRate(t *testing.T) {
	runner := &stepCounterRunner{steps: []string{
		"1000\n2000\n",
		"3000\n2500\n",
	}}
	client := openwrt.New(runner, time.Second, "/tmp/dhcp.leases", "/proc/net/nf_conntrack", 100, "/etc/sing-box/config.json", "")
	connections := NewConnectionsService(client, "ignoreVpn", "ignoreLanToVpn")
	collect := NewCollectService(connections, nil, time.Second, "wan")

	collect.sampleThroughput(context.Background())
	if sample := collect.CurrentThroughput(); sample.UpdatedAt != "" {
		t.Fatalf("expected no sample after first read, got %+v", sample)
	}

	collect.lastSampleAt = time.Now().Add(-2 * time.Second)
	collect.sampleThroughput(context.Background())

	sample := collect.CurrentThroughput()
	if sample.UpdatedAt == "" {
		t.Fatal("expected a sample after the second read")
	}
	if sample.DownloadBytesPerSec <= 0 || sample.UploadBytesPerSec <= 0 {
		t.Fatalf("expected positive rates, got %+v", sample)
	}
}

func TestCollectServiceSampleCPUComputesUsage(t *testing.T) {
	runner := &stepCounterRunner{steps: []string{
		"cpu  100 0 50 800 10 0 0 0 0 0\n",
		"cpu  200 0 50 850 10 0 0 0 0 0\n",
	}}
	client := openwrt.New(runner, time.Second, "/tmp/dhcp.leases", "/proc/net/nf_conntrack", 100, "/etc/sing-box/config.json", "")
	connections := NewConnectionsService(client, "ignoreVpn", "ignoreLanToVpn")
	collect := NewCollectService(connections, nil, time.Second, "wan")

	collect.sampleCPU(context.Background())
	if usage := collect.CurrentCPUUsagePercent(); usage != 0 {
		t.Fatalf("expected no usage after first read, got %v", usage)
	}

	collect.sampleCPU(context.Background())

	usage := collect.CurrentCPUUsagePercent()
	if usage <= 0 || usage >= 100 {
		t.Fatalf("expected usage between 0 and 100, got %v", usage)
	}
}
