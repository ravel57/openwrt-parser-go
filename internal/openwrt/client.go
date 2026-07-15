package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ListKind string

const (
	ListKindDestination ListKind = "destination"
	ListKindSource      ListKind = "source"
)

type ListSpec struct {
	Name      string
	Kind      ListKind
	Interface string
}

type Client struct {
	runner         Runner
	timeout        time.Duration
	dhcpLeasesPath string
	conntrackPath  string
	dnsLogLines    int
	specs          map[string]ListSpec
	dnsMu          sync.RWMutex
	dnsByIP        map[string]string
}

func New(runner Runner, timeout time.Duration, dhcpLeasesPath, conntrackPath string, dnsLogLines int, specs ...ListSpec) *Client {
	m := make(map[string]ListSpec, len(specs))
	for _, s := range specs {
		m[s.Name] = s
	}
	return &Client{runner: runner, timeout: timeout, dhcpLeasesPath: dhcpLeasesPath, conntrackPath: conntrackPath, dnsLogLines: dnsLogLines, specs: m, dnsByIP: map[string]string{}}
}

func (c *Client) Close() error { return c.runner.Close() }

func (c *Client) run(ctx context.Context, script string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return c.runner.Run(ctx, script)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

var dnsLogRE = regexp.MustCompile(`(?i)\bdnsmasq(?:\[[0-9]+\])?:\s+(?:reply|cached|config)\s+([^\s]+)\s+is\s+([^\s]+)`)

func parseDNSLog(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		m := dnsLogRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m[1])), ".")
		ip := strings.TrimSpace(m[2])
		parsed := net.ParseIP(ip)
		if name == "" || parsed == nil || parsed.To4() == nil {
			continue
		}
		out[ip] = name
	}
	return out
}

func (c *Client) DNSCache(ctx context.Context) ([]map[string]string, error) {
	cmd := fmt.Sprintf("logread -e dnsmasq 2>/dev/null | tail -n %d", c.dnsLogLines)
	text, err := c.run(ctx, cmd)
	if err != nil {
		return nil, err
	}
	fresh := parseDNSLog(text)
	c.dnsMu.Lock()
	for ip, name := range fresh {
		c.dnsByIP[ip] = name
	}
	snapshot := make(map[string]string, len(c.dnsByIP))
	for ip, name := range c.dnsByIP {
		snapshot[ip] = name
	}
	c.dnsMu.Unlock()

	keys := make([]string, 0, len(snapshot))
	for ip := range snapshot {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	rows := make([]map[string]string, 0, len(keys))
	for _, ip := range keys {
		rows = append(rows, map[string]string{"data": ip, "name": snapshot[ip]})
	}
	return rows, nil
}

func parseDHCPLeases(text string) []map[string]string {
	var rows []map[string]string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		host := f[3]
		if host == "*" {
			host = ""
		}
		rows = append(rows, map[string]string{"address": f[2], "active-address": f[2], "host-name": host, "active-host-name": host, "mac-address": f[1]})
	}
	return rows
}

func (c *Client) DHCPLeases(ctx context.Context) ([]map[string]string, error) {
	text, err := c.run(ctx, "cat "+shellQuote(c.dhcpLeasesPath)+" 2>/dev/null || true")
	if err != nil {
		return nil, err
	}
	return parseDHCPLeases(text), nil
}

func parseConntrack(text string) []map[string]string {
	out := make([]map[string]string, 0)
	seen := map[string]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		src, dst := "", ""
		for _, f := range fields {
			if strings.HasPrefix(f, "src=") && src == "" {
				src = strings.TrimPrefix(f, "src=")
				continue
			}
			if strings.HasPrefix(f, "dst=") && dst == "" {
				dst = strings.TrimPrefix(f, "dst=")
				if src != "" {
					break
				}
			}
		}
		if net.ParseIP(src) == nil || net.ParseIP(dst) == nil {
			continue
		}
		if net.ParseIP(src).To4() == nil || net.ParseIP(dst).To4() == nil {
			continue
		}
		key := src + "\x00" + dst
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, map[string]string{"src-address": src, "dst-address": dst})
	}
	return out
}

func (c *Client) FirewallConnections(ctx context.Context) ([]map[string]string, error) {
	script := "cat " + shellQuote(c.conntrackPath) + " 2>/dev/null || conntrack -L -o extended 2>/dev/null || true"
	text, err := c.run(ctx, script)
	if err != nil {
		return nil, err
	}
	return parseConntrack(text), nil
}

type uciSection struct {
	ID   string
	Type string
	Opt  map[string]string
}

func unquoteUCI(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, "'\\''", "'")
	}
	return v
}

func parseUCIShow(text string) map[string]*uciSection {
	sections := map[string]*uciSection{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "pbr.") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		left, val := line[:eq], unquoteUCI(line[eq+1:])
		rest := strings.TrimPrefix(left, "pbr.")
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			sec := sections[rest]
			if sec == nil {
				sec = &uciSection{ID: rest, Opt: map[string]string{}}
				sections[rest] = sec
			}
			sec.Type = val
			continue
		}
		id, opt := rest[:dot], rest[dot+1:]
		sec := sections[id]
		if sec == nil {
			sec = &uciSection{ID: id, Opt: map[string]string{}}
			sections[id] = sec
		}
		sec.Opt[opt] = val
	}
	return sections
}

func (c *Client) listSpec(name string) (ListSpec, error) {
	s, ok := c.specs[name]
	if !ok {
		return ListSpec{}, fmt.Errorf("unknown address list %q", name)
	}
	return s, nil
}

func (c *Client) AddressLists(ctx context.Context) ([]ListSpec, error) {
	out := make([]ListSpec, 0, len(c.specs))
	for _, s := range c.specs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *Client) AddressListIgnoreVPN(ctx context.Context, listName string) ([]map[string]string, error) {
	if _, err := c.listSpec(listName); err != nil {
		return nil, err
	}
	text, err := c.run(ctx, "uci -q show pbr || true")
	if err != nil {
		return nil, err
	}
	sections := parseUCIShow(text)
	var rows []map[string]string
	for _, sec := range sections {
		if sec.Type != "policy" || sec.Opt["app_list"] != listName {
			continue
		}
		enabled := sec.Opt["enabled"]
		disabled := "false"
		if enabled == "0" || strings.EqualFold(enabled, "false") {
			disabled = "true"
		}
		address := sec.Opt["app_address"]
		if address == "" {
			if sec.Opt["app_kind"] == string(ListKindSource) {
				address = sec.Opt["src_addr"]
			} else {
				address = sec.Opt["dest_addr"]
			}
		}
		rows = append(rows, map[string]string{".id": sec.ID, "address": address, "disabled": disabled, "dynamic": "false", "comment": sec.Opt["name"], "interface": sec.Opt["interface"], "kind": sec.Opt["app_kind"]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["address"] < rows[j]["address"] })
	return rows, nil
}

func sectionID(listName, address string) string {
	sum := sha256.Sum256([]byte(listName + "\x00" + strings.ToLower(strings.TrimSpace(address))))
	return "app_" + hex.EncodeToString(sum[:8])
}

func (c *Client) AddressListSetDisabled(ctx context.Context, id string, disabled bool) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("empty address-list item id")
	}
	enabled := "1"
	if disabled {
		enabled = "0"
	}
	_, err := c.run(ctx, "uci set pbr."+shellQuote(id)+".enabled="+shellQuote(enabled))
	return err
}

func (c *Client) AddressListAdd(ctx context.Context, listName, address string) error {
	spec, err := c.listSpec(listName)
	if err != nil {
		return err
	}
	address = strings.TrimSpace(address)
	if address == "" {
		return errors.New("empty address")
	}
	id := sectionID(listName, address)
	field := "dest_addr"
	if spec.Kind == ListKindSource {
		field = "src_addr"
	}
	name := fmt.Sprintf("app:%s:%s", listName, address)
	script := strings.Join([]string{
		"uci set pbr." + id + "='policy'",
		"uci set pbr." + id + ".name=" + shellQuote(name),
		"uci set pbr." + id + ".enabled='1'",
		"uci set pbr." + id + ".interface=" + shellQuote(spec.Interface),
		"uci set pbr." + id + ".proto='all'",
		"uci set pbr." + id + ".chain='prerouting'",
		"uci set pbr." + id + "." + field + "=" + shellQuote(address),
		"uci set pbr." + id + ".app_list=" + shellQuote(listName),
		"uci set pbr." + id + ".app_kind=" + shellQuote(string(spec.Kind)),
		"uci set pbr." + id + ".app_address=" + shellQuote(address),
	}, "\n")
	_, err = c.run(ctx, script)
	return err
}

func (c *Client) AddressListDelete(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("empty address-list item id")
	}
	_, err := c.run(ctx, "uci -q delete pbr."+shellQuote(id)+" || true")
	return err
}

func (c *Client) CommitAddressLists(ctx context.Context) error {
	_, err := c.run(ctx, "uci commit pbr && (/etc/init.d/pbr reload >/dev/null 2>&1 || /etc/init.d/pbr restart)")
	return err
}

func SplitDomainsCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func ParseEnabled(v string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(v))
	return b || v == "1"
}
