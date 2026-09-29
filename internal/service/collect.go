package service

import (
	"context"
	"sort"
	"strings"
	"time"

	"openwrt-parser-go/internal/storage"
)

type CollectService struct {
	connections *ConnectionsService
	repo        *storage.Sqlite
	interval    time.Duration
}

func NewCollectService(connections *ConnectionsService, repo *storage.Sqlite, interval time.Duration) *CollectService {
	return &CollectService{connections: connections, repo: repo, interval: interval}
}

func (c *CollectService) Run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()

	type key struct {
		ip  string
		dns string
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			conns, err := c.connections.GetConnections(ctx)
			if err != nil {
				continue
			}

			// DNS -> count
			mDNS := map[string]int64{}
			// (IP,DNS) -> count
			mDst := map[key]int64{}

			for _, cn := range conns {
				dns := strings.TrimSpace(cn.DstDNS)
				if dns == "" {
					continue
				}
				ip := strings.TrimSpace(cn.DstIP)
				if ip == "" {
					continue
				}
				mDNS[dns]++
				mDst[key{ip: ip, dns: dns}]++
			}

			// Keep DNS replies even when the corresponding connection has already
			// disappeared from conntrack. Such entries are shown with zero active
			// connections and can still be added to an address list from the UI.
			dnsRows, dnsErr := c.connections.ow.DNSCache(ctx)
			if dnsErr == nil {
				for _, row := range dnsRows {
					ip := strings.TrimSpace(row["data"])
					dns := strings.TrimSpace(row["name"])
					if dns == "" {
						continue
					}
					if _, exists := mDNS[dns]; !exists {
						mDNS[dns] = 0
					}
					if ip != "" {
						k := key{ip: ip, dns: dns}
						if _, exists := mDst[k]; !exists {
							mDst[k] = 0
						}
					}
				}
			}

			domainCounts := make([]storage.DomainCount, 0, len(mDNS))
			for dns, cnt := range mDNS {
				domainCounts = append(domainCounts, storage.DomainCount{DstDNS: dns, Count: cnt})
			}

			dstCounts := make([]storage.DstCount, 0, len(mDst))
			for k, cnt := range mDst {
				dstCounts = append(dstCounts, storage.DstCount{DstIP: k.ip, DstDNS: k.dns, Count: cnt})
			}

			_ = c.repo.UpsertDomainCounts(ctx, domainCounts)
			_ = c.repo.UpsertDstCounts(ctx, dstCounts)
		}
	}
}

func (c *CollectService) GetByDNS(ctx context.Context, name string) ([]map[string]any, error) {
	rows, err := c.repo.FindDstCountsLike(ctx, name)
	if err != nil {
		return nil, err
	}

	type agg struct {
		dns      string
		sum      int64
		updated  string
		ipsSeen  map[string]struct{}
		ipsSlice []map[string]any
	}

	byDNS := map[string]*agg{}
	for _, r := range rows {
		dns := strings.TrimSpace(r.DstDNS)
		ip := strings.TrimSpace(r.DstIP)
		if dns == "" || ip == "" {
			continue
		}

		key := strings.ToLower(dns)
		a := byDNS[key]
		if a == nil {
			a = &agg{dns: dns, ipsSeen: map[string]struct{}{}, ipsSlice: []map[string]any{}}
			byDNS[key] = a
		}

		a.sum += r.Count
		if r.UpdatedAt > a.updated {
			a.updated = r.UpdatedAt
		}
		if _, exists := a.ipsSeen[ip]; !exists {
			a.ipsSeen[ip] = struct{}{}
			a.ipsSlice = append(a.ipsSlice, map[string]any{"dstIP": ip, "dstDNS": dns})
		}
	}

	domainRows, err := c.repo.FindDomainCountsLike(ctx, name)
	if err != nil {
		return nil, err
	}
	for _, r := range domainRows {
		dns := strings.TrimSpace(r.DstDNS)
		if dns == "" {
			continue
		}
		key := strings.ToLower(dns)
		a := byDNS[key]
		if a == nil {
			a = &agg{dns: dns, ipsSeen: map[string]struct{}{}, ipsSlice: []map[string]any{}}
			byDNS[key] = a
		}
		// domain_conn_counts contains the total count for the hostname, while
		// dst_conn_counts may contain several address rows. Keep the greater
		// value instead of counting the same connections twice.
		if r.Count > a.sum {
			a.sum = r.Count
		}
		if r.UpdatedAt > a.updated {
			a.updated = r.UpdatedAt
		}
	}

	out := make([]map[string]any, 0, len(byDNS))
	indexByDNS := map[string]int{}
	for key, a := range byDNS {
		enabled, _ := c.connections.IsIgnoreVPN(ctx, a.dns)
		indexByDNS[key] = len(out)
		out = append(out, map[string]any{
			"dstDns":            a.dns,
			"activeConnections": a.sum,
			"dnsConnections":    a.ipsSlice,
			"isIgnoreVpn":       enabled,
			"updatedAt":         a.updated,
		})
	}

	// Always include persistent PBR items, even when no active connection was
	// sampled into SQLite. This makes add/enable/disable immediately visible in
	// the existing DNS search screen.
	addressList, err := c.connections.GetAddressList(ctx, c.connections.ignoreVPNListName, name)
	if err != nil {
		return nil, err
	}
	for _, item := range addressList {
		dns := strings.TrimSpace(item.Address)
		if dns == "" {
			continue
		}
		key := strings.ToLower(dns)
		if index, exists := indexByDNS[key]; exists {
			out[index]["isIgnoreVpn"] = item.Enabled
			continue
		}
		indexByDNS[key] = len(out)
		out = append(out, map[string]any{
			"dstDns":            dns,
			"activeConnections": int64(0),
			"dnsConnections":    []map[string]any{},
			"isIgnoreVpn":       item.Enabled,
			"updatedAt":         "",
		})
	}

	sort.Slice(out, func(i, j int) bool {
		left := out[i]["activeConnections"].(int64)
		right := out[j]["activeConnections"].(int64)
		if left == right {
			return strings.ToLower(out[i]["dstDns"].(string)) < strings.ToLower(out[j]["dstDns"].(string))
		}
		return left > right
	})

	return out, nil
}
