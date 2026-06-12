package engine

import "time"

// EN: ProbeReport is the final JSON structure for local storage or analytics
// RU: ProbeReport — финальная структура JSON для сохранения или отправки
type ProbeReport struct {
	Timestamp       time.Time `json:"timestamp"`
	TargetHost      string    `json:"target_host"`
	Results         Results   `json:"results"`
	Recommendations []string  `json:"recommendations"`
}

// EN: Results aggregates output from all probe modules
// RU: Results объединяет результаты всех модулей зонда
type Results struct {
	DNS       DNSResult       `json:"dns"`
	Transport TransportResult `json:"transport"`
	DPI       DPIResult       `json:"dpi"`
}

// EN: DNSResult contains data for DNS spoofing and TLS IP validation
// RU: DNSResult хранит данные о подмене DNS и валидности сертификатов IP
type DNSResult struct {
	ResolvedIPs      []string `json:"resolved_ips"`
	DoHSuccess       bool     `json:"doh_success"`
	TLSCertValid     bool     `json:"tls_cert_valid"`
	SpoofingDetected bool     `json:"spoofing_detected"`
	Errors           []string `json:"errors,omitempty"`
}

// EN: TransportResult checks raw connectivity for baseline protocols
// RU: TransportResult проверяет базовую доступность протоколов
type TransportResult struct {
	TCP443Open  bool     `json:"tcp_443_open"`
	UDP53Works  bool     `json:"udp_53_works"`
	UDP443Works bool     `json:"udp_443_works"`
	Errors      []string `json:"errors,omitempty"`
}

// EN: DPIResult stores heuristics for Deep Packet Inspection (SNI and HTTP Host)
// RU: DPIResult хранит данные эвристик Deep Packet Inspection
type DPIResult struct {
	SNIBlocked  bool     `json:"sni_blocked"`
	HTTPBlocked bool     `json:"http_blocked"`
	BlockMethod string   `json:"block_method,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}
