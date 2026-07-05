package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DonationPayload is what the client POSTs to the collector: a batch of anonymized
// reports. No IPs, no identifiers (see Anonymize).
type DonationPayload struct {
	SchemaVersion int          `json:"schema_version"`
	Reports       []AnonReport `json:"reports"`
}

// HTTPSink uploads anonymized reports to a collector, bootstrapping the TLS connection to
// a hardcoded IP (bypassing system DNS) so a blocked/hijacked collector domain cannot stop
// delivery — the same trick used for DoH in resolver.go. Point bootstrapIP at any
// Cloudflare anycast edge IP; CF routes by SNI/Host, so the exact edge IP does not matter.
//
// The collector (behind the CDN) derives coarse vantage (ASN/country) from the source IP
// and must NEVER store the raw IP.
type HTTPSink struct {
	endpoint string
	client   *http.Client
}

// NewHTTPSink dials bootstrapIP directly but performs the TLS handshake with sni.
func NewHTTPSink(endpointURL, bootstrapIP, sni string) *HTTPSink {
	ip, port, err := net.SplitHostPort(bootstrapIP)
	if err != nil {
		ip, port = bootstrapIP, "443"
	}
	return &HTTPSink{
		endpoint: endpointURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
				},
				TLSClientConfig: &tls.Config{ServerName: sni},
			},
		},
	}
}

// SendBatch delivers a batch of anonymized reports. Callers may ignore the error
// (fail-silent) — a dropped donation must never disrupt the user.
func (s *HTTPSink) SendBatch(ctx context.Context, reports []AnonReport) error {
	body, err := json.Marshal(DonationPayload{SchemaVersion: SchemaVersion, Reports: reports})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("collector returned %d", resp.StatusCode)
	}
	return nil
}

// Report implements TelemetrySink for the always-on opt-in path: fire-and-forget so it
// never blocks a scan. The primary "donate" button should use SendBatch after preview.
func (s *HTTPSink) Report(a AnonReport) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.SendBatch(ctx, []AnonReport{a})
	}()
}
