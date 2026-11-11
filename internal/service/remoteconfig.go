package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"openwrt-parser-go/internal/openwrt"
)

const (
	settingKeyUltunnelSecretKey      = "ultunnel_secret_key"
	settingKeyUltunnelActiveServer   = "ultunnel_active_server"
	settingKeyUltunnelActiveProtocol = "ultunnel_active_protocol"
)

type SettingsStore interface {
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

type RemoteServerConfig struct {
	Protocol string `json:"protocol"`
	Active   bool   `json:"active"`
}

type RemoteServer struct {
	Name    string               `json:"server"`
	Configs []RemoteServerConfig `json:"configs"`
}

type remoteServerResp struct {
	Server  string   `json:"server"`
	Configs []string `json:"configs"`
}

type RemoteConfigService struct {
	httpClient *http.Client
	baseURL    string
	platform   string
	store      SettingsStore
	singBox    *SingBoxService
}

func NewRemoteConfigService(store SettingsStore, singBox *SingBoxService, baseURL, platform string) *RemoteConfigService {
	return &RemoteConfigService{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		baseURL:    baseURL,
		platform:   platform,
		store:      store,
		singBox:    singBox,
	}
}

func (s *RemoteConfigService) HasSecretKey(ctx context.Context) (bool, error) {
	v, ok, err := s.store.GetSetting(ctx, settingKeyUltunnelSecretKey)
	if err != nil {
		return false, err
	}
	return ok && v != "", nil
}

func (s *RemoteConfigService) SetSecretKey(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("secret key must not be empty")
	}
	return s.store.SetSetting(ctx, settingKeyUltunnelSecretKey, key)
}

func (s *RemoteConfigService) secretKey(ctx context.Context) (string, error) {
	v, _, err := s.store.GetSetting(ctx, settingKeyUltunnelSecretKey)
	return v, err
}

// ListServers fetches the list of proxy servers available for the stored
// secret key, with each config's detected protocol instead of the raw
// sing-box JSON.
func (s *RemoteConfigService) ListServers(ctx context.Context) ([]RemoteServer, error) {
	raw, err := s.fetchRaw(ctx)
	if err != nil {
		return nil, err
	}

	activeServer, activeProtocol, err := s.activeSelection(ctx)
	if err != nil {
		return nil, err
	}

	servers := make([]RemoteServer, 0, len(raw))
	for _, item := range raw {
		configs := make([]RemoteServerConfig, 0, len(item.Configs))
		for _, c := range item.Configs {
			protocol := detectProtocol(c)
			configs = append(configs, RemoteServerConfig{
				Protocol: protocol,
				Active:   item.Server == activeServer && protocol == activeProtocol,
			})
		}
		servers = append(servers, RemoteServer{Name: item.Server, Configs: configs})
	}
	return servers, nil
}

// ActiveSelection returns the last successfully applied (server, protocol)
// pair without contacting the remote configs server.
func (s *RemoteConfigService) ActiveSelection(ctx context.Context) (server, protocol string, err error) {
	return s.activeSelection(ctx)
}

func (s *RemoteConfigService) activeSelection(ctx context.Context) (server, protocol string, err error) {
	server, _, err = s.store.GetSetting(ctx, settingKeyUltunnelActiveServer)
	if err != nil {
		return "", "", err
	}
	protocol, _, err = s.store.GetSetting(ctx, settingKeyUltunnelActiveProtocol)
	if err != nil {
		return "", "", err
	}
	return server, protocol, nil
}

// ApplyConfig re-fetches the remote list, picks the config matching
// serverName+protocol and installs it the same way a manually uploaded
// config was installed before.
func (s *RemoteConfigService) ApplyConfig(ctx context.Context, serverName, protocol string) (openwrt.SingBoxStatus, error) {
	serverName = strings.TrimSpace(serverName)
	protocol = strings.TrimSpace(protocol)
	if serverName == "" || protocol == "" {
		return openwrt.SingBoxStatus{}, errors.New("server and protocol are required")
	}

	raw, err := s.fetchRaw(ctx)
	if err != nil {
		return openwrt.SingBoxStatus{}, err
	}

	for _, item := range raw {
		if item.Server != serverName {
			continue
		}
		for _, c := range item.Configs {
			if detectProtocol(c) == protocol {
				status, err := s.singBox.Install(ctx, []byte(c))
				if err != nil {
					return openwrt.SingBoxStatus{}, err
				}
				if err := s.store.SetSetting(ctx, settingKeyUltunnelActiveServer, serverName); err != nil {
					return openwrt.SingBoxStatus{}, err
				}
				if err := s.store.SetSetting(ctx, settingKeyUltunnelActiveProtocol, protocol); err != nil {
					return openwrt.SingBoxStatus{}, err
				}
				return status, nil
			}
		}
		return openwrt.SingBoxStatus{}, fmt.Errorf("protocol %q is not available for server %q", protocol, serverName)
	}
	return openwrt.SingBoxStatus{}, fmt.Errorf("server %q was not found", serverName)
}

func (s *RemoteConfigService) fetchRaw(ctx context.Context) ([]remoteServerResp, error) {
	secretKey, err := s.secretKey(ctx)
	if err != nil {
		return nil, err
	}
	if secretKey == "" {
		return nil, errors.New("secret key is not configured")
	}

	u, err := url.Parse(s.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid remote configs URL: %w", err)
	}
	q := u.Query()
	q.Set("secretKey", secretKey)
	q.Set("platform", s.platform)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to remote configs server failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read remote configs response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote configs server returned status %d", resp.StatusCode)
	}

	var out []remoteServerResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid response from remote configs server: %w", err)
	}
	return out, nil
}

// detectProtocol inspects the outbound/endpoint tagged "proxy" inside a
// sing-box config and returns its type, e.g. "naive", "hysteria2", "wireguard".
func detectProtocol(rawConfig string) string {
	var cfg struct {
		Outbounds []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		} `json:"outbounds"`
		Endpoints []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(rawConfig), &cfg); err != nil {
		return "unknown"
	}
	for _, o := range cfg.Outbounds {
		if o.Tag == "proxy" {
			return o.Type
		}
	}
	for _, e := range cfg.Endpoints {
		if e.Tag == "proxy" {
			return e.Type
		}
	}
	return "unknown"
}
