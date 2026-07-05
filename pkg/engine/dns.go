package engine

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// EN: CheckDNS tests for DNS spoofing and IP blocking.
// RU: CheckDNS проверяет наличие DNS-спуфинга и блокировки по IP.
func CheckDNS(ctx context.Context, cleanIP string, targetHost string) DNSResult {
	result := DNSResult{
		ResolvedIPs:      []string{},
		DoHSuccess:       false,
		TLSCertValid:     false,
		SpoofingDetected: false,
		Errors:           []string{},
	}

	// EN: 1. Direct UDP Query (Bypasses OS cache).
	// RU: 1. Прямой UDP запрос (чтобы обойти кэш ОС).
	// EN: We send the query to a clean IP on port 53.
	// RU: Отправляем запрос на доверенный IP (cleanIP) на порт 53.
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(targetHost), dns.TypeA)

	r, _, err := c.Exchange(m, net.JoinHostPort(cleanIP, "53"))
	if err == nil && r != nil && len(r.Answer) > 0 {
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				result.ResolvedIPs = append(result.ResolvedIPs, a.A.String())
			}
		}
	} else {
		// EN: Fallback to DoH directly if port 53 is blocked (never use net.LookupHost in mobile VPNs)
		// RU: Фолбэк на DoH, так как системный net.LookupHost на Android/iOS вызовет луп.
		ips, err := GetTrustedDoH(ctx, targetHost)
		if err == nil && len(ips) > 0 {
			result.ResolvedIPs = ips
			result.DoHSuccess = true
		} else {
			result.Errors = append(result.Errors, "DNS Error: all resolvers failed")
			return result
		}
	}

	if len(result.ResolvedIPs) == 0 {
		result.Errors = append(result.Errors, "Failed to resolve IPs.")
		return result
	}

	// EN: Verify against DoH only if we haven't already fallen back to it
	// RU: Проверяем через DoH, только если мы еще не переключились на него
	if !result.DoHSuccess {
		dohIPs, err := GetTrustedDoH(ctx, targetHost)
		if err == nil && len(dohIPs) > 0 {
			result.DoHSuccess = true
		}
	}

	// EN: 3. Verify TLS certificate against the first system IP.
	// RU: 3. Проверяем TLS сертификат. Это единственный точный способ отличить CDN от спуфинга.
	if len(result.ResolvedIPs) > 0 {
		targetIP := result.ResolvedIPs[0]
		certValid, tlsErr := verifyTLS(ctx, targetIP, targetHost)

		result.TLSCertValid = certValid

		if tlsErr != nil {
			errStr := tlsErr.Error()
			// EN: A certificate error means the IP served the WRONG cert — a real
			// interceptor / blockpage. That is genuine DNS spoofing.
			if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") || strings.Contains(errStr, "authority") {
				result.SpoofingDetected = true
				result.Errors = append(result.Errors, "[Warning] TLS Cert Invalid. DNS Spoofing detected!")
				// EN: If spoofed, overwrite with DoH IPs so transport tests hit the real servers.
				if result.DoHSuccess {
					dohIPs, _ := GetTrustedDoH(ctx, targetHost)
					if len(dohIPs) > 0 {
						result.ResolvedIPs = dohIPs
					}
				}
			} else {
				// EN: RST/timeout on the real IP is TLS-layer blocking (DPI or IP filtering),
				// EN: NOT DNS spoofing. Previously this was mislabelled as spoofing (a false
				// EN: positive on CDN/anycast targets). Record it honestly instead.
				result.TLSBlocked = true
				result.Errors = append(result.Errors, "[Warning] TLS to real IP failed — DPI/IP block, not spoofing: "+errStr)
			}
		}
	}

	return result
}

// EN: verifyTLS establishes a connection and verifies the certificate
// RU: verifyTLS устанавливает соединение и проверяет сертификат
func verifyTLS(ctx context.Context, ip string, hostname string) (bool, error) {
	pctx, cancel := destProbeCtx(ctx)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(pctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, err
	}

	config := &tls.Config{
		ServerName: hostname, // EN: Ensure server provides valid certificate for the target domain
	}
	tlsConn := tls.Client(conn, config)
	defer tlsConn.Close() // EN: This will also close the underlying conn

	if deadline, ok := pctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}

	err = tlsConn.Handshake()
	if err != nil {
		return false, err
	}

	return true, nil
}
