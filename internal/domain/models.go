package domain

type Connection struct {
	SrcIP     string `json:"srcIP"`
	DstIP     string `json:"dstIP"`
	DstDNS    string `json:"dstDNS"`
	HostName  string `json:"hostName"`
	CreatedAt string `json:"createdAt,omitempty"`
}

type DnsConnection struct {
	DstIP       string `json:"dstIP"`
	DstDNS      string `json:"dstDNS"`
	IsIgnoreVPN bool   `json:"isIgnoreVpn"`
}

type GroupedDnsConnection struct {
	DstDNS      string          `json:"dstDns"`
	Items       []DnsConnection `json:"items"`
	IsIgnoreVPN bool            `json:"isIgnoreVpn"`
}

type HostConnection struct {
	SrcIP       string       `json:"srcIP"`
	HostName    string       `json:"hostName"`
	Connections []Connection `json:"connections"`
}
