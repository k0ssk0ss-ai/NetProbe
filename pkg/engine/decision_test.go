package engine

import "testing"

// matrix is a tiny helper to build a Survivability Matrix for tests.
func matrix(pairs ...[2]string) []FingerprintResult {
	var out []FingerprintResult
	rtt := 50.0
	for _, p := range pairs {
		out = append(out, FingerprintResult{Profile: p[0], Verdict: p[1], RTTMs: rtt})
		rtt += 10
	}
	return out
}

func sniFilteredReport(m []FingerprintResult) ProbeReport {
	var r ProbeReport
	r.Results.DPI.SNIBlocked = true
	r.FingerprintMatrix = m
	return r
}

// TestDecide_FingerprintOverride is the motivating case: a working VLESS+Reality key
// whose chrome ClientHello is RST-injected, while firefox survives. The engine must
// pick that outbound and override the fingerprint to firefox — no human debugging.
func TestDecide_FingerprintOverride(t *testing.T) {
	report := sniFilteredReport(matrix(
		[2]string{"chrome", FPVerdictRST},
		[2]string{"firefox", FPVerdictPass}, // lowest RTT PASS → bestPass
		[2]string{"safari", FPVerdictPass},
		[2]string{"ios", FPVerdictPass},
		[2]string{"edge", FPVerdictPass},
	))
	cands := []OutboundCandidate{
		{ID: "vless-reality", Protocol: "vless", Security: "reality", Fingerprint: "chrome", Port: 443, Transport: "tcp"},
	}

	dec := DecideOutbound(report, cands)
	if dec == nil {
		t.Fatal("expected a decision, got nil")
	}
	if dec.ChosenOutboundID != "vless-reality" {
		t.Errorf("chosen = %q, want vless-reality", dec.ChosenOutboundID)
	}
	if dec.Overrides.Fingerprint != "firefox" {
		t.Errorf("override fingerprint = %q, want firefox", dec.Overrides.Fingerprint)
	}
}

// TestDecide_PrefersRealityUnderKeywordFilter: when every browser fingerprint is RST'd
// (SNI-keyword / IP filtering, not JA3), Reality's borrowed serverName wins over plain TLS.
func TestDecide_PrefersRealityUnderKeywordFilter(t *testing.T) {
	report := sniFilteredReport(matrix(
		[2]string{"chrome", FPVerdictRST},
		[2]string{"firefox", FPVerdictRST},
		[2]string{"safari", FPVerdictRST},
		[2]string{"ios", FPVerdictRST},
		[2]string{"edge", FPVerdictRST},
	))
	cands := []OutboundCandidate{
		{ID: "plain-tls", Protocol: "vless", Security: "tls", Fingerprint: "chrome", Port: 443, Transport: "tcp"},
		{ID: "reality", Protocol: "vless", Security: "reality", Fingerprint: "chrome", Port: 443, Transport: "tcp"},
	}

	dec := DecideOutbound(report, cands)
	if dec.ChosenOutboundID != "reality" {
		t.Errorf("chosen = %q, want reality", dec.ChosenOutboundID)
	}
	if dec.Overrides.Fingerprint != "" {
		t.Errorf("unexpected fingerprint override %q (all fingerprints blocked)", dec.Overrides.Fingerprint)
	}
}

// TestDecide_UDPBlockedDeprioritizesQUIC: with all UDP blocked, a QUIC protocol loses
// to a TCP-based one.
func TestDecide_UDPBlockedDeprioritizesQUIC(t *testing.T) {
	var report ProbeReport // clean DPI, no UDP
	cands := []OutboundCandidate{
		{ID: "hy2", Protocol: "hysteria2", Port: 443, Transport: "quic"},
		{ID: "vless-tcp", Protocol: "vless", Security: "reality", Port: 443, Transport: "tcp"},
	}

	dec := DecideOutbound(report, cands)
	if dec.ChosenOutboundID != "vless-tcp" {
		t.Errorf("chosen = %q, want vless-tcp (UDP blocked)", dec.ChosenOutboundID)
	}
}

// TestDecide_UDP443ThrottlePortOverride: QUIC on 443 throttled but a high UDP port is
// server-allowed → the engine overrides the port instead of abandoning the protocol.
func TestDecide_UDP443ThrottlePortOverride(t *testing.T) {
	var report ProbeReport
	report.Results.Transport.UDP53Works = true // some UDP works
	report.Results.Transport.UDP443Works = false
	cands := []OutboundCandidate{
		{ID: "hy2", Protocol: "hysteria2", Port: 443, Transport: "quic", AllowedPorts: []int{443, 48443}},
	}

	dec := DecideOutbound(report, cands)
	if dec.Overrides.Port != 48443 {
		t.Errorf("override port = %d, want 48443", dec.Overrides.Port)
	}
}

// TestDecide_CleanPrefersLightweight: on a clean network, WireGuard beats a heavy TLS proxy.
func TestDecide_CleanPrefersLightweight(t *testing.T) {
	var report ProbeReport
	report.Results.Transport.UDP53Works = true
	report.Results.Transport.UDP443Works = true
	cands := []OutboundCandidate{
		{ID: "wg", Protocol: "wireguard", Port: 51820, Transport: "udp"},
		{ID: "reality", Protocol: "vless", Security: "reality", Port: 443, Transport: "tcp"},
	}

	dec := DecideOutbound(report, cands)
	if dec.ChosenOutboundID != "wg" {
		t.Errorf("chosen = %q, want wg (clean network)", dec.ChosenOutboundID)
	}
}

func TestDecide_NoCandidates(t *testing.T) {
	if dec := DecideOutbound(ProbeReport{}, nil); dec != nil {
		t.Errorf("expected nil for no candidates, got %+v", dec)
	}
}
