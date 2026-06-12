package engine

import "time"

// ProbeReport contains the final results of the scan
type ProbeReport struct {
	Timestamp       time.Time       `json:"timestamp"`
	TargetHost      string          `json:"target_host"`
	Results         Results         `json:"results"`
	Recommendations []string        `json:"recommendations"`
}

type Results struct {
	DNS       DNSResult       `json:"dns"`
	Transport TransportResult `json:"transport"`
	DPI       DPIResult       `json:"dpi"`
}

// DNSResult stores DNS analysis
type DNSResult struct {
	ResolvedIPs      []string `json:"resolved_ips"`
	DoHSuccess       bool     `json:"doh_success"`
	TLSCertValid     bool     `json:"tls_cert_valid"`
	SpoofingDetected bool     `json:"spoofing_detected"`
	Errors           []string `json:"errors,omitempty"`
}

// TransportResult stores TCP and UDP reachability and QoS metrics
type TransportResult struct {
	TCP443Open  bool     `json:"tcp_443_open"`
	UDP53Works  bool     `json:"udp_53_works"`
	UDP443Works bool     `json:"udp_443_works"`

	TCPRTTAvgMs      float64 `json:"tcp_rtt_avg_ms,omitempty"`
	TCPJitterMs      float64 `json:"tcp_jitter_ms,omitempty"`
	UDPRTTMs         float64 `json:"udp_rtt_ms,omitempty"`
	NATType          string  `json:"nat_type,omitempty"`
	IsUDPShaped      bool    `json:"is_udp_shaped,omitempty"`
	UDPShapingReason string  `json:"udp_shaping_reason,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

// DPIResult stores heuristics for Deep Packet Inspection (SNI and HTTP Host)
type DPIResult struct {
	SNIBlocked    bool   `json:"sni_blocked"`
	HTTPBlocked   bool   `json:"http_blocked"`
	BlockMethod   string `json:"block_method,omitempty"`
	LikelyDPIInjected bool `json:"likely_dpi_injected,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}
