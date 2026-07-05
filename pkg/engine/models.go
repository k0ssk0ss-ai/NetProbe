package engine

import "time"

// SchemaVersion is the frozen version of the NetworkInterferenceReport contract.
// Integrators (Swift/Kotlin/Go) code against this shape; bump only on breaking changes.
const SchemaVersion = 1

// Fingerprint survivability verdicts (populated in Phase 1).
const (
	FPVerdictPass      = "PASS"      // handshake reached TLS/cert stage — this ClientHello survives
	FPVerdictRST       = "RST"       // reset by peer / injected — this fingerprint is blocked
	FPVerdictBlackhole = "BLACKHOLE" // timeout / dropped — silent block
	FPVerdictOther     = "OTHER"     // inconclusive (network error, not censorship)
)

// ProbeReport contains the final results of the scan.
// This is the versioned public contract — see ROADMAP.md §5.
type ProbeReport struct {
	SchemaVersion     int                 `json:"schema_version"`
	Timestamp         time.Time           `json:"timestamp"`
	TargetHost        string              `json:"target_host"`
	Vantage           *Vantage            `json:"vantage,omitempty"` // filled only when telemetry is opt-in (Vector B)
	Results           Results             `json:"results"`
	Endpoints         []EndpointResult    `json:"endpoints,omitempty"`          // secondary app endpoints (gateway/voice/CDN)
	FingerprintMatrix []FingerprintResult `json:"fingerprint_matrix,omitempty"` // Phase 1
	Decision          *Decision           `json:"decision,omitempty"`           // Phase 2 (Vector A)
	Recommendations   []string            `json:"recommendations"`
}

// EndpointResult reports TLS reachability of one secondary endpoint of an app. A landing
// domain reachable via CDN does not mean the app works — its gateway/voice/CDN live
// elsewhere and are often what actually gets blocked.
type EndpointResult struct {
	Host        string `json:"host"`
	Role        string `json:"role,omitempty"` // gateway, cdn, media, ...
	Reachable   bool   `json:"reachable"`
	BlockMethod string `json:"block_method,omitempty"` // RST / BLACKHOLE / OTHER when unreachable
}

// Vantage holds coarse network origin. Populated only with explicit telemetry opt-in.
type Vantage struct {
	ASN     string `json:"asn,omitempty"`
	Country string `json:"country,omitempty"`
}

// FingerprintResult is one cell of the Survivability Matrix: whether a given
// uTLS ClientHello profile passes the current network path. Populated in Phase 1.
type FingerprintResult struct {
	Profile string  `json:"profile"`         // uTLS profile, e.g. "chrome", "firefox", "safari"
	JA3     string  `json:"ja3,omitempty"`   // JA3 hash of the emitted ClientHello
	JA4     string  `json:"ja4,omitempty"`   // JA4 fingerprint of the emitted ClientHello
	Verdict string  `json:"verdict"`         // one of FPVerdict* constants
	RTTMs   float64 `json:"rtt_ms,omitempty"`
}

// Decision is the actionable output of Vector A: which outbound to use and which
// client-tunable parameters to override. Only FREE/CONSTRAINED fields are touched,
// never server-bound ones (uuid, pbk, sid, flow). Populated in Phase 2.
type Decision struct {
	ChosenOutboundID string            `json:"chosen_outbound_id"`
	Overrides        DecisionOverrides `json:"overrides,omitempty"`
	Reason           string            `json:"reason"`
	Alternatives     []string          `json:"alternatives,omitempty"`
}

// DecisionOverrides carries only client-tunable parameters (see ROADMAP.md §6 /
// the parameter-mutability model): fingerprint & fragment are FREE, sni/port/dial_ip
// are CONSTRAINED to the server-allowed set.
type DecisionOverrides struct {
	Fingerprint string `json:"fingerprint,omitempty"` // FREE: uTLS profile
	Fragment    bool   `json:"fragment,omitempty"`    // FREE: TLS record fragmentation
	SNI         string `json:"sni,omitempty"`         // CONSTRAINED: must be a server-allowed serverName
	Port        int    `json:"port,omitempty"`        // CONSTRAINED: must be a server-listened port
	DialIP      string `json:"dial_ip,omitempty"`     // CONSTRAINED: clean entry IP (CDN-fronted setups)
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
	// TLSBlocked marks that TLS to the target's real IP failed by RST/timeout — i.e.
	// destination-aware DPI/IP filtering, NOT DNS spoofing. Set on the real IP path so
	// TLS-layer blocking is no longer mislabelled as spoofing.
	TLSBlocked bool     `json:"tls_blocked,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// TransportResult stores TCP and UDP reachability and QoS metrics
type TransportResult struct {
	TCP443Open  bool `json:"tcp_443_open"`
	UDP53Works  bool `json:"udp_53_works"`
	UDP443Works bool `json:"udp_443_works"`

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
	SNIBlocked        bool     `json:"sni_blocked"`
	HTTPBlocked       bool     `json:"http_blocked"`
	BlockMethod       string   `json:"block_method,omitempty"`
	LikelyDPIInjected bool     `json:"likely_dpi_injected,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}
