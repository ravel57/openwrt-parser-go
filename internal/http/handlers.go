package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"openwrt-parser-go/internal/service"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	connections            *service.ConnectionsService
	collect                *service.CollectService
	staticDir              string
	ignoreVPNListName      string
	ignoreLanToVpnListName string
}

func NewHandler(
	connections *service.ConnectionsService,
	collect *service.CollectService,
	staticDir string,
	ignoreVPNListName string,
	ignoreLanToVpnListName string,
) *Handler {
	return &Handler{
		connections:            connections,
		collect:                collect,
		staticDir:              staticDir,
		ignoreVPNListName:      ignoreVPNListName,
		ignoreLanToVpnListName: ignoreLanToVpnListName,
	}
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
