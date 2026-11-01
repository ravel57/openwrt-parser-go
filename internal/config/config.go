package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPPort  string
	SqliteDSN string

	OpenWrtMode            string
	OpenWrtAddr            string
	OpenWrtUser            string
	OpenWrtPass            string
	OpenWrtKeyFile         string
	OpenWrtInsecureHostKey bool
	OpenWrtCommandTimeout  time.Duration
	OpenWrtDHCPLeasesPath  string
	OpenWrtConntrackPath   string
	OpenWrtDNSLogLines     int
	SingBoxConfigPath      string
	SingBoxApplyCommand    string

	IgnoreVPNListName       string
	IgnoreLanToVpnListName  string
	IgnoreVPNInterface      string
	IgnoreLanToVpnInterface string

	CollectInterval time.Duration
	StaticDir       string
}

func envBool(name string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func Load() Config {
	collectSeconds := envInt("APP_COLLECT_SECONDS", 10)
	timeoutSeconds := envInt("APP_OPENWRT_COMMAND_TIMEOUT_SECONDS", 12)

	mode := strings.ToLower(strings.TrimSpace(os.Getenv("APP_OPENWRT_MODE")))
	addr := strings.TrimSpace(os.Getenv("APP_OPENWRT_ADDR"))
	if mode == "" {
		if addr == "" {
			mode = "local"
		} else {
			mode = "ssh"
		}
	}

	port := strings.TrimSpace(os.Getenv("APP_HTTP_PORT"))
	if port == "" {
		port = "8080"
	}

	staticDir := strings.TrimSpace(os.Getenv("APP_STATIC_DIR"))
	if staticDir == "" {
		staticDir = "web/dist"
	}

	ignoreVPN := strings.TrimSpace(os.Getenv("APP_IGNORE_VPN_LIST"))
	if ignoreVPN == "" {
		ignoreVPN = "ignoreVpn"
	}
	ignoreClient := strings.TrimSpace(os.Getenv("APP_IGNORE_LAN_TO_VPN_LIST"))
	if ignoreClient == "" {
		ignoreClient = "ignoreLanToVpn"
	}

	directInterface := strings.TrimSpace(os.Getenv("APP_OPENWRT_DIRECT_INTERFACE"))
	if directInterface == "" {
		directInterface = "wan"
	}
	ignoreVPNInterface := strings.TrimSpace(os.Getenv("APP_IGNORE_VPN_INTERFACE"))
	if ignoreVPNInterface == "" {
		ignoreVPNInterface = directInterface
	}
	ignoreClientInterface := strings.TrimSpace(os.Getenv("APP_IGNORE_LAN_TO_VPN_INTERFACE"))
	if ignoreClientInterface == "" {
		ignoreClientInterface = directInterface
	}

	user := strings.TrimSpace(os.Getenv("APP_OPENWRT_USER"))
	if user == "" {
		user = "root"
	}

	leasePath := strings.TrimSpace(os.Getenv("APP_OPENWRT_DHCP_LEASES_PATH"))
	if leasePath == "" {
		leasePath = "/tmp/dhcp.leases"
	}
	conntrackPath := strings.TrimSpace(os.Getenv("APP_OPENWRT_CONNTRACK_PATH"))
	if conntrackPath == "" {
		conntrackPath = "/proc/net/nf_conntrack"
	}
	singBoxConfigPath := strings.TrimSpace(os.Getenv("APP_SINGBOX_CONFIG_PATH"))
	if singBoxConfigPath == "" {
		singBoxConfigPath = "/etc/sing-box/config.json"
	}
	singBoxApplyCommand := strings.TrimSpace(os.Getenv("APP_SINGBOX_APPLY_COMMAND"))
	if singBoxApplyCommand == "" {
		singBoxApplyCommand = "/usr/libexec/lan-mode-vpn-setup"
	}

	return Config{
		HTTPPort:                port,
		SqliteDSN:               strings.TrimSpace(os.Getenv("APP_SQLITE_DSN")),
		OpenWrtMode:             mode,
		OpenWrtAddr:             addr,
		OpenWrtUser:             user,
		OpenWrtPass:             os.Getenv("APP_OPENWRT_PASSWORD"),
		OpenWrtKeyFile:          strings.TrimSpace(os.Getenv("APP_OPENWRT_KEY_FILE")),
		OpenWrtInsecureHostKey:  envBool("APP_OPENWRT_INSECURE_HOST_KEY", true),
		OpenWrtCommandTimeout:   time.Duration(timeoutSeconds) * time.Second,
		OpenWrtDHCPLeasesPath:   leasePath,
		OpenWrtConntrackPath:    conntrackPath,
		OpenWrtDNSLogLines:      envInt("APP_OPENWRT_DNS_LOG_LINES", 4000),
		SingBoxConfigPath:       singBoxConfigPath,
		SingBoxApplyCommand:     singBoxApplyCommand,
		IgnoreVPNListName:       ignoreVPN,
		IgnoreLanToVpnListName:  ignoreClient,
		IgnoreVPNInterface:      ignoreVPNInterface,
		IgnoreLanToVpnInterface: ignoreClientInterface,
		CollectInterval:         time.Duration(collectSeconds) * time.Second,
		StaticDir:               staticDir,
	}
}
