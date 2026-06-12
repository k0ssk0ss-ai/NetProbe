package engine

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
)

// EN: CheckDNS tests for DNS spoofing and IP blocking.
// RU: CheckDNS проверяет наличие DNS-спуфинга и блокировки по IP.
func CheckDNS(ctx context.Context, targetHost string) DNSResult {
	result := DNSResult{
		ResolvedIPs:      []string{},
		DoHSuccess:       false,
		TLSCertValid:     false,
		SpoofingDetected: false,
		Errors:           []string{},
	}

	// EN: 1. Direct UDP Query (Bypasses OS cache).
	// RU: 1. Прямой UDP запрос (чтобы обойти кэш ОС).
	// EN: We send the query to 8.8.8.8. ISPs with DPI often intercept port 53 (Transparent DNS Proxy).
	// RU: Отправляем на 8.8.8.8. Провайдеры с DPI часто перехватывают 53 порт.
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(targetHost), dns.TypeA)
	
	r, _, err := c.Exchange(m, "8.8.8.8:53")
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
			matchFound := false
			for _, sysIP := range result.ResolvedIPs {
				for _, trustIP := range dohIPs {
					if sysIP == trustIP {
						matchFound = true
						break
					}
				}
			}
			if !matchFound {
				result.SpoofingDetected = true
				result.Errors = append(result.Errors, "[Warning] System IP does not match DoH IP. Possible DNS spoofing.")
			}
		}
	}

	// EN: 3. Verify TLS certificate.
	// RU: 3. Проверяем TLS сертификат.
	// EN: This is the ultimate proof that the IP belongs to the target domain, not an ISP block page.
	// RU: Это 100% способ убедиться, что IP настоящий, а не провайдерская заглушка.
	targetIP := result.ResolvedIPs[0]
	certValid, tlsErr := verifyTLS(ctx, targetIP, targetHost)
	
	result.TLSCertValid = certValid
	
	if tlsErr != nil {
		result.Errors = append(result.Errors, "TLS Cert Error: "+tlsErr.Error())
		result.SpoofingDetected = true
	}

	return result
}

// EN: verifyTLS establishes a connection and verifies the certificate
// RU: verifyTLS устанавливает соединение и проверяет сертификат
func verifyTLS(ctx context.Context, ip string, hostname string) (bool, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	config := &tls.Config{
		ServerName: hostname, // EN: Ensure server provides valid certificate for the target domain
	}
	tlsConn := tls.Client(conn, config)
	defer tlsConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}
	
	err = tlsConn.Handshake()
	if err != nil {
		return false, err
	}

	return true, nil
}
