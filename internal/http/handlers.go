package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openwrt-parser-go/internal/service"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

type Handler struct {
	connections            *service.ConnectionsService
	collect                *service.CollectService
	singBox                *service.SingBoxService
	remoteConfig           *service.RemoteConfigService
	stats                  *service.StatsService
	staticDir              string
	ignoreVPNListName      string
	ignoreLanToVpnListName string
	statsPushInterval      time.Duration
}

func NewHandler(
	connections *service.ConnectionsService,
	collect *service.CollectService,
	singBox *service.SingBoxService,
	remoteConfig *service.RemoteConfigService,
	stats *service.StatsService,
	staticDir string,
	ignoreVPNListName string,
	ignoreLanToVpnListName string,
	statsPushInterval time.Duration,
) *Handler {
	return &Handler{
		connections:            connections,
		collect:                collect,
		singBox:                singBox,
		remoteConfig:           remoteConfig,
		stats:                  stats,
		staticDir:              staticDir,
		ignoreVPNListName:      ignoreVPNListName,
		ignoreLanToVpnListName: ignoreLanToVpnListName,
		statsPushInterval:      statsPushInterval,
	}
}

var statsWSUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()

	// API
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/config", h.getConfig)
		r.Get("/src", h.getSrc)                            // ?srcIp=
		r.Get("/dns", h.getByDNS)                          // ?find=
		r.Post("/dns", h.postDNS)                          // ?dns=&enabled=
		r.Get("/ignore-lan-to-vpn", h.getIgnoreLanToVpn)   // ?find=
		r.Post("/ignore-lan-to-vpn", h.postIgnoreLanToVpn) // JSON {ip, enabled}
		r.Get("/address-lists/{listName}", h.getAddressList)
		r.Post("/address-lists/{listName}", h.postAddressList)
		r.Delete("/address-lists/{listName}", h.deleteAddressList)
		r.Get("/sing-box/config", h.getSingBoxConfig)
		r.Post("/sing-box/config", h.postSingBoxConfig)
		r.Get("/remote-configs/secret-key", h.getRemoteConfigSecretKey)
		r.Post("/remote-configs/secret-key", h.postRemoteConfigSecretKey)
		r.Get("/remote-configs/servers", h.getRemoteConfigServers)
		r.Post("/remote-configs/apply", h.postRemoteConfigApply)
		r.Get("/stats", h.getStats)
		r.Get("/stats/ws", h.getStatsWS)
	})

	// Frontend (как в Spring: "/" -> index, + /js/**, /css/**, /favicon.ico)
	if h.staticDir != "" && dirExists(h.staticDir) {
		fs := http.FileServer(http.Dir(h.staticDir))

		// точечные роуты как в MvcConfig
		r.Get("/", h.serveIndex)
		r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(h.staticDir, "favicon.ico"))
		})
		r.Handle("/js/*", fs)
		r.Handle("/css/*", fs)

		// если во фронте есть другие ассеты (images/fonts и т.п.)
		r.Handle("/assets/*", fs)

		// SPA fallback: любой неизвестный путь (кроме /api/*) -> index.html
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			h.serveIndex(w, r)
		})
	}

	return r
}

func (h *Handler) getSingBoxConfig(w http.ResponseWriter, r *http.Request) {
	status, err := h.singBox.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *Handler) postSingBoxConfig(w http.ResponseWriter, r *http.Request) {
	const multipartOverhead = 256 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, service.MaxSingBoxConfigSize+multipartOverhead)
	if err := r.ParseMultipartForm(256 * 1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid or oversized multipart upload"})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, header, err := r.FormFile("config")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "multipart field 'config' is required"})
		return
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, service.MaxSingBoxConfigSize+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to read uploaded file"})
		return
	}
	if int64(len(contents)) > service.MaxSingBoxConfigSize {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "configuration file is larger than 1 MiB"})
		return
	}

	status, err := h.singBox.Install(r.Context(), contents)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"fileName":   filepath.Base(header.Filename),
		"configured": status.Configured,
		"path":       status.Path,
		"size":       status.Size,
		"running":    status.Running,
	})
}

func (h *Handler) getRemoteConfigSecretKey(w http.ResponseWriter, r *http.Request) {
	configured, err := h.remoteConfig.HasSecretKey(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": configured})
}

type secretKeyReq struct {
	SecretKey string `json:"secretKey"`
}

func (h *Handler) postRemoteConfigSecretKey(w http.ResponseWriter, r *http.Request) {
	var req secretKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if err := h.remoteConfig.SetSecretKey(r.Context(), req.SecretKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) getRemoteConfigServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.remoteConfig.ListServers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, servers)
}

type applyRemoteConfigReq struct {
	Server   string `json:"server"`
	Protocol string `json:"protocol"`
}

func (h *Handler) postRemoteConfigApply(w http.ResponseWriter, r *http.Request) {
	var req applyRemoteConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	status, err := h.remoteConfig.ApplyConfig(r.Context(), req.Server, req.Protocol)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"server":     req.Server,
		"protocol":   req.Protocol,
		"configured": status.Configured,
		"path":       status.Path,
		"size":       status.Size,
		"running":    status.Running,
	})
}

func (h *Handler) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.stats.Get(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// getStatsWS pushes a fresh Stats snapshot to the client right away and then
// again on every tick, until the socket is closed, so the UI can stay live
// without polling.
func (h *Handler) getStatsWS(w http.ResponseWriter, r *http.Request) {
	conn, err := statsWSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx := r.Context()
	interval := h.statsPushInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	sendStats := func() bool {
		stats, err := h.stats.Get(ctx)
		if err != nil {
			return true
		}
		return conn.WriteJSON(stats) == nil
	}

	if !sendStats() {
		return
	}

	// WriteJSON isn't safe to call concurrently with reads, but we only need
	// the read loop to notice when the client goes away (close frame, pings,
	// or a dropped connection).
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if !sendStats() {
				return
			}
		}
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(h.staticDir, "index.html"))
}

type configResp struct {
	RouterType             string `json:"routerType"`
	IgnoreVPNListName      string `json:"ignoreVPNListName"`
	IgnoreLanToVpnListName string `json:"ignoreLanToVpnListName"`
}

func (h *Handler) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, configResp{
		RouterType:             "openwrt",
		IgnoreVPNListName:      h.ignoreVPNListName,
		IgnoreLanToVpnListName: h.ignoreLanToVpnListName,
	})
}

func (h *Handler) getSrc(w http.ResponseWriter, r *http.Request) {
	srcIP := r.URL.Query().Get("srcIp")
	res, err := h.connections.GetBySrc(r.Context(), srcIP)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, res)
}

func (h *Handler) getByDNS(w http.ResponseWriter, r *http.Request) {
	find := r.URL.Query().Get("find")
	res, err := h.collect.GetByDNS(r.Context(), find)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, res)
}

func (h *Handler) postDNS(w http.ResponseWriter, r *http.Request) {
	dns := r.URL.Query().Get("dns")
	enabled := r.URL.Query().Get("enabled") == "true"

	if err := h.connections.PostDnsToIgnoreList(r.Context(), dns, enabled); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

type ignoreLanToVpnReq struct {
	IP       string `json:"ip"`
	Enabled  bool   `json:"enabled"`
	HostName string `json:"hostName,omitempty"`
}

func (h *Handler) getIgnoreLanToVpn(w http.ResponseWriter, r *http.Request) {
	find := r.URL.Query().Get("find")
	items, err := h.connections.GetIgnoreLanToVpn(r.Context(), find)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, items)
}

func (h *Handler) postIgnoreLanToVpn(w http.ResponseWriter, r *http.Request) {
	// поддержка и query, и JSON
	ip := r.URL.Query().Get("ip")
	enabledStr := r.URL.Query().Get("enabled")

	var req ignoreLanToVpnReq
	if ip == "" {
		_ = json.NewDecoder(r.Body).Decode(&req)
		ip = req.IP
		if enabledStr == "" {
			if req.Enabled {
				enabledStr = "true"
			} else {
				enabledStr = "false"
			}
		}
	}

	enabled := enabledStr == "true" || enabledStr == "1"
	if err := h.connections.PostIpToIgnoreLanToVpn(r.Context(), ip, enabled); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

type addressListReq struct {
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

func (h *Handler) getAddressList(w http.ResponseWriter, r *http.Request) {
	listName := chi.URLParam(r, "listName")
	items, err := h.connections.GetAddressList(r.Context(), listName, r.URL.Query().Get("find"))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, items)
}

func (h *Handler) postAddressList(w http.ResponseWriter, r *http.Request) {
	listName := chi.URLParam(r, "listName")
	req := addressListReq{Address: r.URL.Query().Get("address"), Enabled: r.URL.Query().Get("enabled") == "true" || r.URL.Query().Get("enabled") == "1"}
	if req.Address == "" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
	}
	if err := h.connections.SetAddressListItem(r.Context(), listName, req.Address, req.Enabled); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "address": req.Address, "enabled": req.Enabled})
}

func (h *Handler) deleteAddressList(w http.ResponseWriter, r *http.Request) {
	listName := chi.URLParam(r, "listName")
	address := r.URL.Query().Get("address")
	if address == "" {
		var req addressListReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		address = req.Address
	}
	if err := h.connections.DeleteAddressListItem(r.Context(), listName, address); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
