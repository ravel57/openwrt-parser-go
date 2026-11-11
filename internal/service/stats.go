package service

import (
	"context"

	"openwrt-parser-go/internal/storage"
)

const topDomainsLimit = 10

type ListStats struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
}

type SingBoxStats struct {
	Configured     bool   `json:"configured"`
	Running        bool   `json:"running"`
	ActiveServer   string `json:"activeServer"`
	ActiveProtocol string `json:"activeProtocol"`
}

type TopDomainStat struct {
	DstDNS            string `json:"dstDns"`
	ActiveConnections int64  `json:"activeConnections"`
	UpdatedAt         string `json:"updatedAt"`
}

type ConnectionsStats struct {
	TrackedDomains      int64           `json:"trackedDomains"`
	TrackedDestinations int64           `json:"trackedDestinations"`
	ActiveConnections   int64           `json:"activeConnections"`
	TopDomains          []TopDomainStat `json:"topDomains"`
}

type NetworkStats struct {
	DownloadBytesPerSec float64 `json:"downloadBytesPerSec"`
	UploadBytesPerSec   float64 `json:"uploadBytesPerSec"`
	UpdatedAt           string  `json:"updatedAt"`
}

type SystemStats struct {
	UptimeSeconds  float64 `json:"uptimeSeconds"`
	LoadAvg1       float64 `json:"loadAvg1"`
	MemUsedPercent float64 `json:"memUsedPercent"`
	CPUUsedPercent float64 `json:"cpuUsedPercent"`
}

type Stats struct {
	SingBox     SingBoxStats     `json:"singBox"`
	Connections ConnectionsStats `json:"connections"`
	Network     NetworkStats     `json:"network"`
	System      SystemStats      `json:"system"`
	IgnoreVPN   ListStats        `json:"ignoreVpn"`
	IgnoreLAN   ListStats        `json:"ignoreLanToVpn"`
}

type StatsService struct {
	connections            *ConnectionsService
	singBox                *SingBoxService
	remoteConfig           *RemoteConfigService
	collect                *CollectService
	repo                   *storage.Sqlite
	ignoreVPNListName      string
	ignoreLanToVpnListName string
}

func NewStatsService(
	connections *ConnectionsService,
	singBox *SingBoxService,
	remoteConfig *RemoteConfigService,
	collect *CollectService,
	repo *storage.Sqlite,
	ignoreVPNListName string,
	ignoreLanToVpnListName string,
) *StatsService {
	return &StatsService{
		connections:            connections,
		singBox:                singBox,
		remoteConfig:           remoteConfig,
		collect:                collect,
		repo:                   repo,
		ignoreVPNListName:      ignoreVPNListName,
		ignoreLanToVpnListName: ignoreLanToVpnListName,
	}
}

func (s *StatsService) Get(ctx context.Context) (Stats, error) {
	var out Stats

	if status, err := s.singBox.Status(ctx); err == nil {
		out.SingBox.Configured = status.Configured
		out.SingBox.Running = status.Running
	}
	if server, protocol, err := s.remoteConfig.ActiveSelection(ctx); err == nil {
		out.SingBox.ActiveServer = server
		out.SingBox.ActiveProtocol = protocol
	}

	out.IgnoreVPN = s.listStats(ctx, s.ignoreVPNListName)
	out.IgnoreLAN = s.listStats(ctx, s.ignoreLanToVpnListName)

	if summary, err := s.repo.DomainStatsSummary(ctx); err == nil {
		out.Connections.TrackedDomains = summary.TrackedDomains
		out.Connections.TrackedDestinations = summary.TrackedDestinations
		out.Connections.ActiveConnections = summary.ActiveConnections
	}
	if top, err := s.repo.TopDomainCounts(ctx, topDomainsLimit); err == nil {
		out.Connections.TopDomains = make([]TopDomainStat, 0, len(top))
		for _, d := range top {
			out.Connections.TopDomains = append(out.Connections.TopDomains, TopDomainStat{
				DstDNS:            d.DstDNS,
				ActiveConnections: d.Count,
				UpdatedAt:         d.UpdatedAt,
			})
		}
	}

	speed := s.collect.CurrentThroughput()
	out.Network.DownloadBytesPerSec = speed.DownloadBytesPerSec
	out.Network.UploadBytesPerSec = speed.UploadBytesPerSec
	out.Network.UpdatedAt = speed.UpdatedAt

	if info, err := s.connections.ow.SystemInfo(ctx); err == nil {
		out.System.UptimeSeconds = info.UptimeSeconds
		out.System.LoadAvg1 = info.LoadAvg1
		if info.MemTotalKB > 0 {
			out.System.MemUsedPercent = 100 * float64(info.MemTotalKB-info.MemAvailableKB) / float64(info.MemTotalKB)
		}
	}
	out.System.CPUUsedPercent = s.collect.CurrentCPUUsagePercent()

	return out, nil
}

func (s *StatsService) listStats(ctx context.Context, listName string) ListStats {
	items, err := s.connections.GetAddressList(ctx, listName, "")
	if err != nil {
		return ListStats{}
	}
	stats := ListStats{Total: len(items)}
	for _, it := range items {
		if it.Enabled {
			stats.Enabled++
		}
	}
	return stats
}
