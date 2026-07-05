package engine

import "fmt"

// EN: AnalyzeResults takes raw telemetry and generates actionable recommendations
// RU: AnalyzeResults принимает сырую телеметрию и выдает массив рекомендаций
func AnalyzeResults(report *ProbeReport) {
	var recs []string

	if report.Results.DPI.SNIBlocked {
		recs = append(recs, "[PROTOCOL] SNI filtering is active. Classic protocols (OpenVPN, WireGuard) are vulnerable. Recommended: VLESS+Reality, Trojan, or Shadowsocks-2022.")
	}

	if report.Results.DPI.HTTPBlocked {
		recs = append(recs, "[HTTP] ISP intercepts unencrypted HTTP Host headers. Avoid transparent proxies without encryption.")
	}

	// EN: UDP viability. Crucially, QUIC-to-a-public-CDN-on-443 timing out does NOT mean
	// EN: "UDP is dead" — that specific pattern is heavily throttled in some regions while
	// EN: arbitrary UDP still works. Cross-check the STUN RTT (UDPRTTMs) as a liveness signal
	// EN: so we don't tell a working custom-port Hysteria/WireGuard user to switch to TCP.
	t := report.Results.Transport
	udpAlive := t.UDP53Works || t.UDP443Works || t.UDPRTTMs > 0
	switch {
	case !udpAlive:
		recs = append(recs, "[TRANSPORT] All UDP appears blocked (no DNS/QUIC/STUN response). UDP-based protocols (WireGuard, Hysteria2, TUIC) will likely fail — prefer TCP-based transports (VLESS/Trojan over TCP).")
	case t.UDP443Works:
		recs = append(recs, "[TRANSPORT] UDP 443 (QUIC) is open — Hysteria2 / TUIC on 443 are ideal for speed and latency.")
	default:
		recs = append(recs, "[TRANSPORT] Standard QUIC on 443 to public servers is throttled, but UDP itself works (STUN/DNS responded). Custom-port UDP protocols — Hysteria2 / WireGuard / TUIC on a non-443 port to your own server — are usually NOT affected. Don't switch away from a working UDP setup based on this signal alone.")
	}

	if report.Results.DNS.TLSBlocked {
		recs = append(recs, "[TLS] Target unreachable at TLS on its real IP (RST/timeout) — destination-aware DPI or IP filtering, not spoofing. Use a protocol that hides the destination (VLESS+Reality, Shadowsocks-2022).")
	}

	if report.Results.DNS.SpoofingDetected {
		recs = append(recs, "[DNS] DNS Spoofing detected (wrong TLS certificate served). Enforce encrypted DNS (DoH/DoT) in your client.")
	}

	// EN: Secondary app endpoints — a reachable landing domain can still mean a dead app
	// if its gateway/CDN is blocked.
	for _, ep := range report.Endpoints {
		if !ep.Reachable {
			recs = append(recs, fmt.Sprintf("[APP] Endpoint %s (%s) is unreachable (%s) — the landing page may load, but the app won't fully work without a proxy.", ep.Host, ep.Role, ep.BlockMethod))
		}
	}

	if len(recs) == 0 {
		recs = append(recs, "[CLEAN] No harsh blocking detected. Any fast protocol (WireGuard, OpenVPN) can be used safely.")
	}

	report.Recommendations = recs
}
