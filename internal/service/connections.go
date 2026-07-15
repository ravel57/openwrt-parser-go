package service

import (
	"context"
	"strconv"
	"strings"
	"time"

	"openwrt-parser-go/internal/domain"
	"openwrt-parser-go/internal/openwrt"
)

type ConnectionsService struct {
	ow *openwrt.Client

	ignoreVPNListName      string
	ignoreLanToVpnListName string
}

func NewConnectionsService(ow *openwrt.Client, ignoreVPNListName, ignoreLanToVpnListName string) *ConnectionsService {
	return &ConnectionsService{
		ow:                     ow,
		ignoreVPNListName:      ignoreVPNListName,
		ignoreLanToVpnListName: ignoreLanToVpnListName,
	}
}

func stripPort(s string) string {
	if strings.Count(s, ":") == 1 {
		i := strings.LastIndex(s, ":")
		if i > 0 {
			if _, err := strconv.Atoi(s[i+1:]); err == nil {
				return s[:i]
			}
		}
	}
	return s
}

func (s *ConnectionsService) GetConnections(ctx context.Context) ([]domain.Connection, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	dnsRows, err := s.ow.DNSCache(ctx)
	if err != nil {
		return nil, err
	}
	leaseRows, err := s.ow.DHCPLeases(ctx)
	if err != nil {
		return nil, err
	}
	connRows, err := s.ow.FirewallConnections(ctx)
	if err != nil {
		return nil, err
	}

	dnsByIP := map[string]string{}
	for _, r := range dnsRows {
		ip := r["data"]
		if ip == "" {
			ip = r["address"]
		}
		name := r["name"]
		if name == "" {
			name = r["dns-name"]
		}
		if ip != "" && name != "" {
			dnsByIP[ip] = name
		}
	}

	hostByIP := map[string]string{}
	for _, r := range leaseRows {
		ip := r["active-address"]
		if ip == "" {
			ip = r["address"]
		}
		host := r["active-host-name"]
		if host == "" {
			host = r["host-name"]
		}
		if host == "" {
			host = r["comment"]
		}
		if ip != "" && host != "" {
			hostByIP[ip] = host
		}
	}

	out := make([]domain.Connection, 0, len(connRows))
	for _, r := range connRows {
		src := stripPort(r["src-address"])
		dst := stripPort(r["dst-address"])
		if src == "" || dst == "" {
			continue
		}
		out = append(out, domain.Connection{
			SrcIP:    src,
			DstIP:    dst,
			DstDNS:   dnsByIP[dst],
			HostName: hostByIP[src],
		})
	}

	// Добавляем DNS-записи даже тогда, когда короткое соединение
	// уже исчезло из conntrack до очередного опроса.
	seenDst := make(map[string]struct{}, len(out))
	for _, connection := range out {
		seenDst[connection.DstIP] = struct{}{}
	}
	for ip, dns := range dnsByIP {
		if _, exists := seenDst[ip]; exists {
			continue
		}

		out = append(out, domain.Connection{
			DstIP:  ip,
			DstDNS: dns,
		})
	}

	return out, nil
}

func (s *ConnectionsService) GetBySrc(ctx context.Context, srcIP string) ([]domain.GroupedDnsConnection, error) {
	conns, err := s.GetConnections(ctx)
	if err != nil {
		return nil, err
	}

	group := map[string][]domain.DnsConnection{}
	for _, c := range conns {
		if c.SrcIP != srcIP {
			continue
		}
		key := c.DstDNS
		group[key] = append(group[key], domain.DnsConnection{DstIP: c.DstIP, DstDNS: c.DstDNS})
	}

	res := make([]domain.GroupedDnsConnection, 0, len(group))
	for dns, items := range group {
		ignore, _ := s.IsIgnoreVPN(ctx, dns)
		res = append(res, domain.GroupedDnsConnection{
			DstDNS:      dns,
			Items:       items,
			IsIgnoreVPN: ignore,
		})
	}
	return res, nil
}

func (s *ConnectionsService) PostDnsToIgnoreList(ctx context.Context, domains string, enabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	addresses, err := s.ow.AddressListIgnoreVPN(ctx, s.ignoreVPNListName)
	if err != nil {
		return err
	}

	byAddress := map[string]map[string]string{}
	for _, r := range addresses {
		if a := r["address"]; a != "" {
			byAddress[a] = r
		}
	}

	for _, domain := range openwrt.SplitDomainsCSV(domains) {
		row := byAddress[domain]
		id := ""
		if row != nil {
			id = row[".id"]
		}

		if enabled {
			if id != "" {
				if err := s.ow.AddressListSetDisabled(ctx, id, false); err != nil {
					return err
				}
			} else {
				if err := s.ow.AddressListAdd(ctx, s.ignoreVPNListName, domain); err != nil {
					return err
				}
			}
		} else {
			if id != "" {
				if err := s.ow.AddressListSetDisabled(ctx, id, true); err != nil {
					return err
				}
			}
		}
	}
	return s.ow.CommitAddressLists(ctx)
}

func (s *ConnectionsService) IsIgnoreVPN(ctx context.Context, dns string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	if strings.TrimSpace(dns) == "" {
		return false, nil
	}

	addresses, err := s.ow.AddressListIgnoreVPN(ctx, s.ignoreVPNListName)
	if err != nil {
		return false, err
	}

	enabledStatic := map[string]bool{}
	for _, r := range addresses {
		if r["dynamic"] == "true" {
			continue
		}
		if r["disabled"] == "true" {
			continue
		}
		if a := r["address"]; a != "" {
			enabledStatic[a] = true
		}
	}

	for _, d := range openwrt.SplitDomainsCSV(dns) {
		if !enabledStatic[d] {
			return false, nil
		}
	}
	return true, nil
}

type IgnoreLanToVpnItem struct {
	IP       string `json:"ip"`
	HostName string `json:"hostName"`
	Enabled  bool   `json:"enabled"`
	Dynamic  bool   `json:"dynamic"`
}

func (s *ConnectionsService) GetIgnoreLanToVpn(ctx context.Context, find string) ([]IgnoreLanToVpnItem, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// адрес-лист ignoreLanToVpn
	addresses, err := s.ow.AddressListIgnoreVPN(ctx, s.ignoreLanToVpnListName) // метод уже есть, просто другой listName
	if err != nil {
		return nil, err
	}

	// DHCP leases для матчинга IP -> active host name
	leaseRows, err := s.ow.DHCPLeases(ctx)
	if err != nil {
		return nil, err
	}

	hostByIP := map[string]string{}
	for _, r := range leaseRows {
		ip := r["active-address"]
		if ip == "" {
			ip = r["address"]
		}
		host := r["active-host-name"]
		if host == "" {
			host = r["host-name"]
		}
		if host == "" {
			host = r["comment"]
		}
		if ip != "" && host != "" {
			hostByIP[ip] = host
		}
	}

	find = strings.ToLower(strings.TrimSpace(find))

	out := make([]IgnoreLanToVpnItem, 0, len(addresses))
	for _, r := range addresses {
		ip := strings.TrimSpace(r["address"])
		if ip == "" {
			continue
		}

		host := hostByIP[ip]
		if host == "" {
			// fallback: если в address-list записан comment
			host = strings.TrimSpace(r["comment"])
		}

		d := strings.ToLower(strings.TrimSpace(r["disabled"]))
		enabled := !(d == "true" || d == "yes")
		dyn := r["dynamic"] == "true"

		// фильтр по ip/hostname (опционально)
		if find != "" {
			if !strings.Contains(strings.ToLower(ip), find) &&
				!strings.Contains(strings.ToLower(host), find) {
				continue
			}
		}

		out = append(out, IgnoreLanToVpnItem{
			IP:       ip,
			HostName: host,
			Enabled:  enabled,
			Dynamic:  dyn,
		})
	}
	return out, nil
}

func (s *ConnectionsService) PostIpToIgnoreLanToVpn(ctx context.Context, ip string, enabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}

	addresses, err := s.ow.AddressListIgnoreVPN(ctx, s.ignoreLanToVpnListName)
	if err != nil {
		return err
	}

	var id string
	for _, r := range addresses {
		if strings.TrimSpace(r["address"]) == ip {
			id = r[".id"]
			break
		}
	}

	if enabled {
		if id != "" {
			if err := s.ow.AddressListSetDisabled(ctx, id, false); err != nil {
				return err
			}
		} else {
			if err := s.ow.AddressListAdd(ctx, s.ignoreLanToVpnListName, ip); err != nil {
				return err
			}
		}
		return s.ow.CommitAddressLists(ctx)
	}

	if id != "" {
		if err := s.ow.AddressListSetDisabled(ctx, id, true); err != nil {
			return err
		}
		return s.ow.CommitAddressLists(ctx)
	}
	return nil
}

type AddressListItem struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
	Dynamic   bool   `json:"dynamic"`
	Kind      string `json:"kind,omitempty"`
	Interface string `json:"interface,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

func (s *ConnectionsService) GetAddressList(ctx context.Context, listName, find string) ([]AddressListItem, error) {
	rows, err := s.ow.AddressListIgnoreVPN(ctx, listName)
	if err != nil {
		return nil, err
	}
	find = strings.ToLower(strings.TrimSpace(find))
	out := make([]AddressListItem, 0, len(rows))
	for _, r := range rows {
		address := strings.TrimSpace(r["address"])
		if find != "" && !strings.Contains(strings.ToLower(address+" "+r["comment"]), find) {
			continue
		}
		out = append(out, AddressListItem{
			ID: r[".id"], Address: address, Enabled: r["disabled"] != "true",
			Dynamic: r["dynamic"] == "true", Kind: r["kind"], Interface: r["interface"], Comment: r["comment"],
		})
	}
	return out, nil
}

func (s *ConnectionsService) SetAddressListItem(ctx context.Context, listName, address string, enabled bool) error {
	rows, err := s.ow.AddressListIgnoreVPN(ctx, listName)
	if err != nil {
		return err
	}
	address = strings.TrimSpace(address)
	var id string
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r["address"]), address) {
			id = r[".id"]
			break
		}
	}
	if id == "" {
		if !enabled {
			return nil
		}
		if err := s.ow.AddressListAdd(ctx, listName, address); err != nil {
			return err
		}
	} else if err := s.ow.AddressListSetDisabled(ctx, id, !enabled); err != nil {
		return err
	}
	return s.ow.CommitAddressLists(ctx)
}

func (s *ConnectionsService) DeleteAddressListItem(ctx context.Context, listName, address string) error {
	rows, err := s.ow.AddressListIgnoreVPN(ctx, listName)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r["address"]), strings.TrimSpace(address)) {
			if err := s.ow.AddressListDelete(ctx, r[".id"]); err != nil {
				return err
			}
			return s.ow.CommitAddressLists(ctx)
		}
	}
	return nil
}
