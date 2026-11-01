package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"openwrt-parser-go/internal/openwrt"
)

type singBoxRunner struct {
	calls  int
	input  []byte
	script string
}

func (r *singBoxRunner) Run(_ context.Context, script string) (string, error) {
	r.calls++
	r.script = script
	return "configured=true\nsize=42\nrunning=true\n", nil
}

func (r *singBoxRunner) RunInput(_ context.Context, script string, input []byte) (string, error) {
	r.calls++
	r.script = script
	r.input = append([]byte(nil), input...)
	return "", nil
}

func (r *singBoxRunner) Close() error { return nil }

func newTestSingBoxService(runner openwrt.Runner) *SingBoxService {
	client := openwrt.New(
		runner,
		time.Second,
		"/tmp/dhcp.leases",
		"/proc/net/nf_conntrack",
		100,
		"/etc/sing-box/config.json",
		"/usr/libexec/lan-mode-vpn-setup",
	)
	return NewSingBoxService(client)
}

func TestSingBoxInstallRejectsInvalidJSONBeforeCallingRouter(t *testing.T) {
	runner := &singBoxRunner{}
	service := newTestSingBoxService(runner)

	_, err := service.Install(context.Background(), []byte(`{"inbounds": [`))
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("router was called %d times for invalid JSON", runner.calls)
	}
}

func TestSingBoxInstallStreamsConfigAndReturnsStatus(t *testing.T) {
	runner := &singBoxRunner{}
	service := newTestSingBoxService(runner)
	config := []byte(`{"inbounds":[],"outbounds":[]}`)

	status, err := service.Install(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Configured || !status.Running || status.Size != 42 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if string(runner.input) != string(config) {
		t.Fatalf("uploaded bytes changed: got %q", runner.input)
	}
	if !strings.Contains(runner.script, "pidof sing-box") {
		t.Fatalf("last router call did not query status: %q", runner.script)
	}
}

type failingSingBoxRunner struct{}

func (failingSingBoxRunner) Run(context.Context, string) (string, error) { return "", nil }
func (failingSingBoxRunner) RunInput(context.Context, string, []byte) (string, error) {
	return "", errors.New("apply failed")
}
func (failingSingBoxRunner) Close() error { return nil }

func TestSingBoxInstallReturnsApplyError(t *testing.T) {
	service := newTestSingBoxService(failingSingBoxRunner{})
	_, err := service.Install(context.Background(), []byte(`{"inbounds":[],"outbounds":[]}`))
	if err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("expected apply error, got %v", err)
	}
}
