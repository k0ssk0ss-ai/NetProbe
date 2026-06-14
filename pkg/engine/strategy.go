package engine

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

	if !report.Results.Transport.UDP53Works && !report.Results.Transport.UDP443Works {
		recs = append(recs, "[TRANSPORT] All standard UDP traffic is blocked or throttled. Pure WireGuard or Hysteria2 on port 443 will fail. Try moving UDP protocols (Hysteria2/VLESS) to non-standard ports (e.g. 48443, 8433), or fallback to TCP.")
	} else if report.Results.Transport.UDP443Works {
		recs = append(recs, "[TRANSPORT] UDP 443 (QUIC) is open! Protocols like Hysteria2 and TUIC on port 443 are highly recommended for maximum speed and latency reduction.")
	} else if report.Results.Transport.UDP53Works && !report.Results.Transport.UDP443Works {
		recs = append(recs, "[TRANSPORT] UDP 53 is open, but UDP 443 (QUIC) is blocked. TSPU throttles standard QUIC. Move Hysteria2/VLESS to custom high ports (e.g. 48443) to bypass DPI, or use TCP.")
	}

	if report.Results.DNS.SpoofingDetected {
		recs = append(recs, "[DNS] DNS Spoofing detected. Configure your client to enforce encrypted DNS (DoH/DoT).")
	}

	if len(recs) == 0 {
		recs = append(recs, "[CLEAN] No harsh blocking detected. Any fast protocol (WireGuard, OpenVPN) can be used safely.")
	}

	report.Recommendations = recs
}
