package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memSettingsStore struct {
	values map[string]string
}

func newMemSettingsStore() *memSettingsStore {
	return &memSettingsStore{values: map[string]string{}}
}

func (m *memSettingsStore) GetSetting(_ context.Context, key string) (string, bool, error) {
	v, ok := m.values[key]
	return v, ok, nil
}

func (m *memSettingsStore) SetSetting(_ context.Context, key, value string) error {
	m.values[key] = value
	return nil
}

func TestRemoteConfigSetSecretKeyRejectsEmpty(t *testing.T) {
	store := newMemSettingsStore()
	svc := NewRemoteConfigService(store, nil, "http://example.invalid", "desktop")

	if err := svc.SetSecretKey(context.Background(), "   "); err == nil {
		t.Fatal("expected error for empty secret key")
	}

	configured, err := svc.HasSecretKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if configured {
		t.Fatal("expected secret key to remain unconfigured")
	}
}

func TestRemoteConfigListServersDetectsProtocols(t *testing.T) {
	naive := `{"outbounds":[{"tag":"proxy","type":"naive"},{"tag":"direct","type":"direct"}]}`
	wireguard := `{"endpoints":[{"tag":"proxy","type":"wireguard"}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("secretKey") != "the-secret" || q.Get("platform") != "desktop" {
			t.Fatalf("unexpected query: %v", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]remoteServerResp{
			{Server: "Netherlands", Configs: []string{naive, wireguard}},
		})
	}))
	defer srv.Close()

	store := newMemSettingsStore()
	svc := NewRemoteConfigService(store, nil, srv.URL, "desktop")
	if err := svc.SetSecretKey(context.Background(), "the-secret"); err != nil {
		t.Fatal(err)
	}

	servers, err := svc.ListServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Name != "Netherlands" {
		t.Fatalf("unexpected servers: %+v", servers)
	}
	if len(servers[0].Configs) != 2 || servers[0].Configs[0].Protocol != "naive" || servers[0].Configs[1].Protocol != "wireguard" {
		t.Fatalf("unexpected configs: %+v", servers[0].Configs)
	}
}

func TestRemoteConfigListServersRequiresSecretKey(t *testing.T) {
	store := newMemSettingsStore()
	svc := NewRemoteConfigService(store, nil, "http://example.invalid", "desktop")

	if _, err := svc.ListServers(context.Background()); err == nil || !strings.Contains(err.Error(), "secret key") {
		t.Fatalf("expected secret key error, got %v", err)
	}
}

func TestRemoteConfigApplyConfigInstallsMatchingProtocol(t *testing.T) {
	naive := `{"outbounds":[{"tag":"proxy","type":"naive"},{"tag":"direct","type":"direct"}]}`
	hysteria := `{"outbounds":[{"tag":"proxy","type":"hysteria2"},{"tag":"direct","type":"direct"}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]remoteServerResp{
			{Server: "France", Configs: []string{naive, hysteria}},
		})
	}))
	defer srv.Close()

	store := newMemSettingsStore()
	store.values[settingKeyUltunnelSecretKey] = "the-secret"

	runner := &singBoxRunner{}
	singBoxSvc := newTestSingBoxService(runner)
	svc := NewRemoteConfigService(store, singBoxSvc, srv.URL, "desktop")

	status, err := svc.ApplyConfig(context.Background(), "France", "hysteria2")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Configured || !status.Running {
		t.Fatalf("unexpected status: %+v", status)
	}
	if string(runner.input) != hysteria {
		t.Fatalf("installed wrong config: %s", runner.input)
	}

	servers, err := svc.ListServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || len(servers[0].Configs) != 2 {
		t.Fatalf("unexpected servers: %+v", servers)
	}
	for _, cfg := range servers[0].Configs {
		wantActive := cfg.Protocol == "hysteria2"
		if cfg.Active != wantActive {
			t.Fatalf("protocol %s: active=%v, want %v", cfg.Protocol, cfg.Active, wantActive)
		}
	}

	if _, err := svc.ApplyConfig(context.Background(), "France", "does-not-exist"); err == nil {
		t.Fatal("expected error for unknown protocol")
	}
	if _, err := svc.ApplyConfig(context.Background(), "Unknown", "naive"); err == nil {
		t.Fatal("expected error for unknown server")
	}
}
