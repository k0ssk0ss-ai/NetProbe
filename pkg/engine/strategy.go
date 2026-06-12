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
		recs = append(recs, "[TRANSPORT] All UDP traffic is blocked or throttled. Avoid pure WireGuard and Hysteria2. Use TCP-based transports (VLESS/Trojan via TCP/ws).")
	} else if report.Results.Transport.UDP443Works {
		recs = append(recs, "[TRANSPORT] UDP 443 (QUIC) is open! Protocols like Hysteria2 and TUIC are highly recommended for maximum speed and latency reduction.")
	} else if report.Results.Transport.UDP53Works && !report.Results.Transport.UDP443Works {
		recs = append(recs, "[TRANSPORT] UDP 53 is open, but UDP 443 (QUIC) is blocked. Avoid Hysteria2. WireGuard might work if 53 is not shaped, but TCP (VLESS) is safer.")
	}

	if report.Results.DNS.SpoofingDetected {
		recs = append(recs, "[DNS] DNS Spoofing detected. Configure your client to enforce encrypted DNS (DoH/DoT).")
	}

	if len(recs) == 0 {
		recs = append(recs, "[CLEAN] No harsh blocking detected. Any fast protocol (WireGuard, OpenVPN) can be used safely.")
	}

	report.Recommendations = recs
}
