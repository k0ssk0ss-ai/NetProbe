package engine

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// OutboundCandidate is a neutral, ecosystem-independent description of one connection
// option the client already has (parsed from the user's subscription). Adapters
// (e.g. pkg/adapter/singbox) convert client-specific configs into these; the core
// decision engine never imports client types. See ROADMAP.md §3, §6.
//
// Fields split by the parameter-mutability model:
//   - server-bound (uuid, pbk, sid, flow) are NOT represented here — the engine never touches them;
//   - the candidate's current SNI/Port/Fingerprint are what the client is using now;
//   - Allowed* / Supports* / CDNFronted describe the client's freedom to vary those.
type OutboundCandidate struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`  // vless, vmess, trojan, shadowsocks, hysteria2, tuic, wireguard
	Transport   string `json:"transport"` // tcp, ws, grpc, http, quic
	Security    string `json:"security"`  // reality, tls, none
	Host        string `json:"host"`
	DestIP      string `json:"dest_ip,omitempty"`
	Port        int    `json:"port"`
	SNI         string `json:"sni,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	// Client-tunable freedoms (ROADMAP.md §6).
	AllowedSNIs      []string `json:"allowed_snis,omitempty"`  // CONSTRAINED: server-allowed serverNames
	AllowedPorts     []int    `json:"allowed_ports,omitempty"` // CONSTRAINED: server-listened ports
	SupportsFragment bool     `json:"supports_fragment,omitempty"`
	CDNFronted       bool     `json:"cdn_fronted,omitempty"`
}

// browserFingerprints are the stable, statically-settable uTLS profiles used for
// decisioning. "randomized" is deliberately excluded: its non-PASS results are
// ambiguous (server alert vs. censorship), so it is noise for a survivability verdict.
var browserFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true, "edge": true,
}

// DecideOutbound ranks the client's outbounds against the observed network conditions
// and returns the best choice plus the client-tunable overrides that make it work.
// This is Vector A: it turns the probe report into an actionable connection decision.
//
// It is a pure function of the report (including the Survivability Matrix) and the
// candidates — deterministic and unit-testable, with no extra network I/O. The matrix
// it consumes is a path-level JA3 signal; per-candidate active probing (accurate mode)
// is the accuracy refinement tracked for the next increment.
func DecideOutbound(report ProbeReport, candidates []OutboundCandidate) *Decision {
	if len(candidates) == 0 {
		return nil
	}

	cond := deriveConditions(report)
	fp := analyzeMatrix(report.FingerprintMatrix)

	type scored struct {
		cand      OutboundCandidate
		score     int
		overrides DecisionOverrides
		reason    string
	}

	ranked := make([]scored, 0, len(candidates))
	for _, c := range candidates {
		s, ov, reason := scoreCandidate(c, cond, fp)
		ranked = append(ranked, scored{cand: c, score: s, overrides: ov, reason: reason})
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		// Tie-break by lower TCP RTT preference is not per-candidate here; keep input order.
		return false
	})

	best := ranked[0]
	dec := &Decision{
		ChosenOutboundID: best.cand.ID,
		Overrides:        best.overrides,
		Reason:           best.reason,
	}
	for _, r := range ranked[1:] {
		dec.Alternatives = append(dec.Alternatives, r.cand.ID)
	}
	return dec
}

// DecideOutboundActive is the accurate-mode variant of DecideOutbound (Vector A): for
// each uTLS candidate it actively probes the fingerprint matrix against THAT candidate's
// own endpoint IP + SNI, instead of relying on the diagnostic target's path-level matrix.
// This is what makes "use fingerprint=firefox for THIS server" trustworthy rather than
// inferred. Non-uTLS candidates (or ones whose IP can't be resolved) fall back to the
// report's global matrix.
func DecideOutboundActive(ctx context.Context, report ProbeReport, candidates []OutboundCandidate) *Decision {
	if len(candidates) == 0 {
		return nil
	}

	cond := deriveConditions(report)
	globalFP := analyzeMatrix(report.FingerprintMatrix)

	type scored struct {
		cand      OutboundCandidate
		score     int
		overrides DecisionOverrides
		reason    string
	}
	ranked := make([]scored, len(candidates))

	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, cand OutboundCandidate) {
			defer wg.Done()

			fp := globalFP
			// EN: Only TCP-based TLS/Reality candidates carry a probeable TCP ClientHello.
			// EN: QUIC protocols (hysteria2/tuic) do their TLS inside UDP — a TCP fingerprint
			// EN: probe of their port is meaningless, so keep the global signal for them.
			if usesUTLS(cand) && !isUDPProtocol(cand) {
				if ip := resolveCandidateIP(ctx, cand); ip != "" {
					sni := cand.SNI
					if sni == "" {
						sni = cand.Host
					}
					fp = analyzeMatrix(CheckFingerprints(ctx, ip, sni))
				}
			}

			s, ov, reason := scoreCandidate(cand, cond, fp)
			ranked[idx] = scored{cand: cand, score: s, overrides: ov, reason: reason}
		}(i, c)
	}
	wg.Wait()

	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].score > ranked[j].score
	})

	best := ranked[0]
	dec := &Decision{
		ChosenOutboundID: best.cand.ID,
		Overrides:        best.overrides,
		Reason:           best.reason,
	}
	for _, r := range ranked[1:] {
		dec.Alternatives = append(dec.Alternatives, r.cand.ID)
	}
	return dec
}

// usesUTLS reports whether a candidate sends a uTLS ClientHello (Reality or plain TLS),
// i.e. whether fingerprint probing is meaningful for it.
func usesUTLS(c OutboundCandidate) bool {
	return strings.EqualFold(c.Security, "reality") || strings.EqualFold(c.Security, "tls")
}

// resolveCandidateIP returns the candidate's endpoint IP: its explicit DestIP, or the
// DoH-resolved Host. Empty if neither is available.
func resolveCandidateIP(ctx context.Context, c OutboundCandidate) string {
	if c.DestIP != "" {
		return c.DestIP
	}
	if c.Host == "" {
		return ""
	}
	if ips, err := GetTrustedDoH(ctx, c.Host); err == nil && len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// conditions is the distilled network state the scorer reasons over.
type conditions struct {
	sniFiltering  bool
	httpIntercept bool
	dnsSpoof      bool
	udp443        bool
	anyUDP        bool
}

func deriveConditions(r ProbeReport) conditions {
	return conditions{
		sniFiltering:  r.Results.DPI.SNIBlocked,
		httpIntercept: r.Results.DPI.HTTPBlocked,
		dnsSpoof:      r.Results.DNS.SpoofingDetected,
		udp443:        r.Results.Transport.UDP443Works,
		anyUDP:        r.Results.Transport.UDP53Works || r.Results.Transport.UDP443Works,
	}
}

// fpAnalysis summarizes the Survivability Matrix over the stable browser profiles.
type fpAnalysis struct {
	anyPass        bool
	anyRST         bool
	allBrowsersRST bool
	bestPass       string // lowest-RTT PASSing browser profile
}

func analyzeMatrix(matrix []FingerprintResult) fpAnalysis {
	var a fpAnalysis
	seen, blocked := 0, 0
	bestRTT := math.MaxFloat64
	for _, r := range matrix {
		if !browserFingerprints[strings.ToLower(r.Profile)] {
			continue
		}
		seen++
		switch r.Verdict {
		case FPVerdictPass:
			a.anyPass = true
			if r.RTTMs < bestRTT {
				bestRTT = r.RTTMs
				a.bestPass = r.Profile
			}
		case FPVerdictRST, FPVerdictBlackhole:
			a.anyRST = true
			blocked++
		}
	}
	a.allBrowsersRST = seen > 0 && blocked == seen
	return a
}

// scoreCandidate assigns a viability score under the observed conditions and, when a
// client-tunable override would help, records it. Higher score = better choice.
func scoreCandidate(c OutboundCandidate, cond conditions, fp fpAnalysis) (int, DecisionOverrides, string) {
	score := 50
	var ov DecisionOverrides
	var reasons []string

	isReality := strings.EqualFold(c.Security, "reality")
	isTLS := strings.EqualFold(c.Security, "tls")
	usesUTLS := isReality || isTLS
	isUDP := isUDPProtocol(c)

	// --- UDP / transport viability ---
	if isUDP {
		switch {
		case !cond.anyUDP:
			score -= 60
			reasons = append(reasons, "all UDP is blocked — this UDP protocol will fail")
		case udpOn443(c) && !cond.udp443:
			if p := firstNonStandardPort(c.AllowedPorts); p != 0 {
				ov.Port = p
				score -= 5
				reasons = append(reasons, fmt.Sprintf("UDP 443 throttled — move to port %d", p))
			} else {
				score -= 30
				reasons = append(reasons, "UDP 443 throttled and no alternate port available")
			}
		case cond.udp443:
			score += 15
			reasons = append(reasons, "UDP/QUIC open — low-latency protocol viable")
		}
	}

	// --- DPI / SNI / fingerprint viability (TCP TLS/Reality only) ---
	// EN: TCP SNI/JA3 DPI does not apply to QUIC protocols — their TLS rides inside UDP,
	// EN: a different filtering surface. UDP protocols are judged on UDP viability above.
	if cond.sniFiltering && !isUDP {
		// Fingerprint (JA3) filtering affects BOTH Reality and plain TLS — both send a
		// uTLS ClientHello. If some browser fingerprints are RST'd but others pass, a
		// fingerprint switch fixes it (the chrome→firefox case).
		if usesUTLS && fp.anyRST && fp.anyPass {
			score += 10
			if fp.bestPass != "" && !strings.EqualFold(fp.bestPass, c.Fingerprint) {
				ov.Fingerprint = fp.bestPass
				reasons = append(reasons, fmt.Sprintf(
					"ClientHello fingerprint '%s' is RST-injected on this ISP; '%s' survives",
					fpOrDefault(c.Fingerprint), fp.bestPass))
			} else {
				reasons = append(reasons, "current fingerprint already survives")
			}
		}

		// SNI-keyword resilience differs by protocol.
		switch {
		case isReality:
			score += 30
			reasons = append(reasons, "Reality resists SNI-keyword filtering (borrowed serverName)")
		case strings.EqualFold(c.Protocol, "shadowsocks"):
			score += 20
			reasons = append(reasons, "Shadowsocks has no TLS SNI to filter")
		case isTLS && fp.allBrowsersRST:
			// Every browser fingerprint dies → SNI-keyword or IP filtering, not JA3.
			switch {
			case c.SupportsFragment:
				ov.Fragment = true
				score += 5
				reasons = append(reasons, "SNI-keyword filtering — TLS fragmentation may bypass")
			case firstAlternateSNI(c) != "":
				ov.SNI = firstAlternateSNI(c)
				score += 3
				reasons = append(reasons, fmt.Sprintf("SNI filtered — switch to allowed serverName '%s'", ov.SNI))
			default:
				score -= 25
				reasons = append(reasons, "plain TLS SNI filtered; no fragmentation or alternate SNI available")
			}
		}
	} else if isUDP || strings.EqualFold(c.Protocol, "wireguard") {
		// Clean network: prefer lightweight, low-latency protocols.
		score += 10
		reasons = append(reasons, "clean network — lightweight protocol preferred")
	}

	if cond.httpIntercept && strings.EqualFold(c.Security, "none") && !isUDP {
		score -= 15
		reasons = append(reasons, "ISP intercepts plaintext — avoid unencrypted transport")
	}

	reason := strings.Join(reasons, "; ")
	if reason == "" {
		reason = "no specific interference affecting this outbound"
	}
	return score, ov, reason
}

func isUDPProtocol(c OutboundCandidate) bool {
	switch strings.ToLower(c.Protocol) {
	case "hysteria2", "hysteria", "tuic", "wireguard":
		return true
	}
	return strings.EqualFold(c.Transport, "quic")
}

// udpOn443 reports whether the candidate rides UDP on port 443, where QUIC/UDP
// shaping (common under TSPU) tends to bite.
func udpOn443(c OutboundCandidate) bool {
	return isUDPProtocol(c) && c.Port == 443
}

func firstNonStandardPort(ports []int) int {
	for _, p := range ports {
		if p != 443 && p != 53 && p != 80 {
			return p
		}
	}
	return 0
}

func firstAlternateSNI(c OutboundCandidate) string {
	for _, s := range c.AllowedSNIs {
		if !strings.EqualFold(s, c.SNI) {
			return s
		}
	}
	return ""
}

func fpOrDefault(fp string) string {
	if fp == "" {
		return "(default)"
	}
	return fp
}
