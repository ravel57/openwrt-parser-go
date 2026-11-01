package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
	runner              Runner
	timeout             time.Duration
	dhcpLeasesPath      string
	conntrackPath       string
	dnsLogLines         int
	singBoxConfigPath   string
	singBoxApplyCommand string
	specs               map[string]ListSpec
	dnsMu               sync.RWMutex
	dnsByIP             map[string]string
	dnsNames            map[string]struct{}
	applyMu             sync.Mutex
	singBoxMu           sync.Mutex
}

func New(runner Runner, timeout time.Duration, dhcpLeasesPath, conntrackPath string, dnsLogLines int, singBoxConfigPath, singBoxApplyCommand string, specs ...ListSpec) *Client {
	m := make(map[string]ListSpec, len(specs))
	for _, s := range specs {
		m[s.Name] = s
	}
	return &Client{
		runner:              runner,
		timeout:             timeout,
		dhcpLeasesPath:      dhcpLeasesPath,
		conntrackPath:       conntrackPath,
		dnsLogLines:         dnsLogLines,
		singBoxConfigPath:   singBoxConfigPath,
		singBoxApplyCommand: singBoxApplyCommand,
		specs:               m,
		dnsByIP:             map[string]string{},
		dnsNames:            map[string]struct{}{},
	}
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

func (c *Client) runInput(ctx context.Context, script string, input []byte) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return c.runner.RunInput(ctx, script, input)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

type SingBoxStatus struct {
	Path       string `json:"path"`
	Configured bool   `json:"configured"`
	Size       int64  `json:"size"`
	Running    bool   `json:"running"`
}

func (c *Client) SingBoxStatus(ctx context.Context) (SingBoxStatus, error) {
	path := c.singBoxConfigPath
	if path == "" {
		return SingBoxStatus{}, errors.New("sing-box config path is not configured")
	}

	script := strings.Join([]string{
		"config=" + shellQuote(path),
		"if [ -s \"$config\" ]; then",
		"  printf 'configured=true\\n'",
		"  printf 'size=%s\\n' \"$(wc -c < \"$config\" | tr -d ' ')\"",
		"else",
		"  printf 'configured=false\\nsize=0\\n'",
		"fi",
		"if pidof sing-box >/dev/null 2>&1; then printf 'running=true\\n'; else printf 'running=false\\n'; fi",
	}, "\n")
	out, err := c.run(ctx, script)
	if err != nil {
		return SingBoxStatus{}, err
	}

	status := SingBoxStatus{Path: path}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "configured":
			status.Configured = value == "true"
		case "size":
			status.Size, _ = strconv.ParseInt(value, 10, 64)
		case "running":
			status.Running = value == "true"
		}
	}
	return status, nil
}

func (c *Client) InstallSingBoxConfig(ctx context.Context, contents []byte) (SingBoxStatus, error) {
	path := c.singBoxConfigPath
	if path == "" {
		return SingBoxStatus{}, errors.New("sing-box config path is not configured")
	}

	c.singBoxMu.Lock()
	defer c.singBoxMu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		applyTimeout := c.timeout
		if applyTimeout < 60*time.Second {
			applyTimeout = 60 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, applyTimeout)
		defer cancel()
	}

	// The uploaded bytes travel through stdin, not through the shell command.
	// This avoids command-length limits and keeps credentials out of process
	// arguments and error messages.
	script := strings.Join([]string{
		"set -eu",
		"config=" + shellQuote(path),
		"apply_command=" + shellQuote(c.singBoxApplyCommand),
		"tmp=\"${config}.upload.$$\"",
		"rollback=\"${config}.rollback.$$\"",
		"apply_log=\"/tmp/openwrt-parser-sing-box-apply.$$\"",
		"had_old=0",
		"cleanup() { rm -f \"$tmp\" \"$rollback\" \"$apply_log\"; }",
		"trap cleanup EXIT INT TERM",
		"mkdir -p \"$(dirname \"$config\")\"",
		"cat > \"$tmp\"",
		"chmod 600 \"$tmp\"",
		"command -v sing-box >/dev/null 2>&1 || { echo 'sing-box is not installed' >&2; exit 1; }",
		"sing-box check -c \"$tmp\"",
		"if [ -f \"$config\" ]; then cp -p \"$config\" \"$rollback\"; had_old=1; fi",
		"mv \"$tmp\" \"$config\"",
		"chmod 600 \"$config\"",
		"set +e",
		"if [ -n \"$apply_command\" ] && [ -x \"$apply_command\" ]; then",
		"  \"$apply_command\" \"$config\" >\"$apply_log\" 2>&1",
		"  apply_rc=$?",
		"elif [ -x /etc/init.d/sing-box ]; then",
		"  /etc/init.d/sing-box restart >\"$apply_log\" 2>&1",
		"  apply_rc=$?",
		"else",
		"  echo 'sing-box init script is not installed' >\"$apply_log\"",
		"  apply_rc=1",
		"fi",
		"if [ \"$apply_rc\" -eq 0 ]; then",
		"  attempts=0",
		"  while [ \"$attempts\" -lt 5 ] && ! pidof sing-box >/dev/null 2>&1; do attempts=$((attempts + 1)); sleep 1; done",
		"  if ! pidof sing-box >/dev/null 2>&1; then echo 'sing-box did not stay running' >>\"$apply_log\"; apply_rc=1; fi",
		"fi",
		"set -e",
		"if [ \"$apply_rc\" -ne 0 ]; then",
		"  cat \"$apply_log\" >&2",
		"  if [ \"$had_old\" -eq 1 ]; then",
		"    cp -p \"$rollback\" \"$config\"",
		"    if [ -n \"$apply_command\" ] && [ -x \"$apply_command\" ]; then \"$apply_command\" \"$config\" >/dev/null 2>&1 || true; else /etc/init.d/sing-box restart >/dev/null 2>&1 || true; fi",
		"  else",
		"    rm -f \"$config\"",
		"    /etc/init.d/sing-box stop >/dev/null 2>&1 || true",
		"  fi",
		"  exit \"$apply_rc\"",
		"fi",
		"if [ \"$had_old\" -eq 1 ]; then cp -p \"$rollback\" \"${config}.before-panel\"; chmod 600 \"${config}.before-panel\"; fi",
	}, "\n")

	if _, err := c.runInput(ctx, script, contents); err != nil {
		return SingBoxStatus{}, err
	}
	return c.SingBoxStatus(ctx)
}

func normalizeDNSName(value string) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	name = strings.Trim(name, "[],")
	if name == "" || net.ParseIP(name) != nil {
		return ""
	}
	if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		return ""
	}
	return name
}

func parseDNSLog(text string) (map[string]string, map[string]struct{}) {
	byIP := map[string]string{}
	names := map[string]struct{}{}

	addName := func(raw string) string {
		name := normalizeDNSName(raw)
		if name != "" {
			names[name] = struct{}{}
		}
		return name
	}

	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields); i++ {
			token := strings.ToLower(fields[i])

			// A browser-visible hostname is present in the query line even when
			// dnsmasq later returns a CNAME. Recording queries prevents the
			// original hostname from being lost in favour of the final CDN name.
			if strings.HasPrefix(token, "query[") && strings.HasSuffix(token, "]") && i+1 < len(fields) {
				queryType := strings.TrimSuffix(strings.TrimPrefix(token, "query["), "]")
				if queryType != "ptr" {
					addName(fields[i+1])
				}
				continue
			}

			if token != "reply" && token != "cached" && token != "config" {
				continue
			}
			if i+3 >= len(fields) || !strings.EqualFold(fields[i+2], "is") {
				continue
			}

			name := addName(fields[i+1])
			if name == "" {
				continue
			}

			ip := strings.Trim(strings.TrimSpace(fields[i+3]), "[],")
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}

			// Keep IPv4 and IPv6 associations. IPv6 may be disabled in PBR,
			// but retaining it is still useful for displaying observed domains.
			byIP[ip] = name
		}
	}
	return byIP, names
}

func (c *Client) DNSCache(ctx context.Context) ([]map[string]string, error) {
	cmd := fmt.Sprintf("logread -e dnsmasq 2>/dev/null | tail -n %d", c.dnsLogLines)
	text, err := c.run(ctx, cmd)
	if err != nil {
		return nil, err
	}

	freshByIP, freshNames := parseDNSLog(text)

	c.dnsMu.Lock()
	for ip, name := range freshByIP {
		c.dnsByIP[ip] = name
	}
	for name := range freshNames {
		c.dnsNames[name] = struct{}{}
	}

	byIP := make(map[string]string, len(c.dnsByIP))
	for ip, name := range c.dnsByIP {
		byIP[ip] = name
	}
	names := make([]string, 0, len(c.dnsNames))
	for name := range c.dnsNames {
		names = append(names, name)
	}
	c.dnsMu.Unlock()

	sort.Strings(names)
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	// A name-only row records every DNS query, including CNAME-based names
	// that have no direct address in the dnsmasq reply log.
	rows := make([]map[string]string, 0, len(names)+len(ips))
	for _, name := range names {
		rows = append(rows, map[string]string{"name": name})
	}
	for _, ip := range ips {
		rows = append(rows, map[string]string{"data": ip, "name": byIP[ip]})
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

func (c *Client) CommitAddressLists(ctx context.Context, listName string, addresses ...string) error {
	spec, err := c.listSpec(listName)
	if err != nil {
		return err
	}

	unique := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		key := strings.ToLower(address)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, address)
	}
	if len(unique) == 0 {
		return nil
	}

	// UCI, PBR reload and conntrack cleanup must not overlap when the UI sends
	// several toggle requests in quick succession.
	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	commands := []string{"set -eu"}

	if spec.Kind == ListKindDestination {
		commands = append(commands,
			"ips_file=/tmp/openwrt-parser-ips.$$",
			"trap 'rm -f \"$ips_file\"' EXIT",
			": > \"$ips_file\"",
		)
		for _, address := range unique {
			lookup := strings.TrimPrefix(address, "*.")
			commands = append(commands,
				"resolveip -4 "+shellQuote(lookup)+" >> \"$ips_file\" 2>/dev/null || true",
			)
		}
	}

	commands = append(commands,
		"uci commit pbr",
		"if /etc/init.d/pbr reload; then :; else /etc/init.d/pbr restart; fi",
	)

	switch spec.Kind {
	case ListKindDestination:
		for _, address := range unique {
			lookup := strings.TrimPrefix(address, "*.")
			commands = append(commands,
				// Query local dnsmasq after the PBR reload. With dnsmasq.nftset
				// this fills the newly created nft set immediately.
				"if command -v nslookup >/dev/null 2>&1; then nslookup "+shellQuote(lookup)+" 127.0.0.1 >/dev/null 2>&1 || true; fi",
				"resolveip -4 "+shellQuote(lookup)+" >> \"$ips_file\" 2>/dev/null || true",
			)
		}
		commands = append(commands,
			// Existing TCP and UDP sessions keep their old routing decision.
			// Remove only sessions to the affected destination addresses.
			"if command -v conntrack >/dev/null 2>&1; then",
			"  awk '/^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/ { print }' \"$ips_file\" | sort -u | while read -r ip; do",
			"    [ -n \"$ip\" ] && conntrack -D -d \"$ip\" >/dev/null 2>&1 || true",
			"  done",
			"fi",
		)
	case ListKindSource:
		commands = append(commands, "if command -v conntrack >/dev/null 2>&1; then")
		for _, address := range unique {
			commands = append(commands,
				"  conntrack -D -s "+shellQuote(address)+" >/dev/null 2>&1 || true",
			)
		}
		commands = append(commands, "fi")
	default:
		return fmt.Errorf("unsupported address-list kind %q", spec.Kind)
	}

	_, err = c.run(ctx, strings.Join(commands, "\n"))
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
