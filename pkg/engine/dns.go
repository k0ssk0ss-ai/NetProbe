package engine

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// EN: CheckDNS tests for DNS spoofing and IP blocking.
// RU: CheckDNS проверяет наличие DNS-спуфинга и блокировки по IP.
func CheckDNS(targetHost string) DNSResult {
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
	c.Timeout = 3 * time.Second
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
		// EN: Fallback to OS resolver if port 53 is completely blocked
		// RU: Фолбэк на системный резолвер, если 53 порт заблокирован намертво
		ips, err := net.LookupHost(targetHost)
		if err == nil && len(ips) > 0 {
			result.ResolvedIPs = ips
		} else {
			result.Errors = append(result.Errors, "DNS Error: "+err.Error())
			return result
		}
	}

	if len(result.ResolvedIPs) == 0 {
		result.Errors = append(result.Errors, "Failed to resolve IPs.")
		return result
	}

	// EN: 2. Query via trusted DoH
	// RU: 2. Запрос через надежный DoH пул
	trustedIPs, err := GetTrustedDoH(targetHost)
	if err == nil && len(trustedIPs) > 0 {
		result.DoHSuccess = true
		matchFound := false
		for _, sysIP := range result.ResolvedIPs {
			for _, trustIP := range trustedIPs {
				if sysIP == trustIP {
					matchFound = true
					break
				}
			}
		}
		if !matchFound {
			result.Errors = append(result.Errors, "[Warning] System IP does not match DoH IP (Possible spoofing)")
		}
	}

	// EN: 3. Verify TLS certificate validity on the resolved IP
	// RU: 3. Проверка валидности TLS-сертификата по выданному IP
	// EN: This is the ultimate proof that the IP belongs to the target domain, not an ISP block page.
	// RU: Это 100% способ убедиться, что IP настоящий, а не провайдерская заглушка.
	targetIP := result.ResolvedIPs[0]
	certValid, tlsErr := verifyTLS(targetIP, targetHost)
	
	result.TLSCertValid = certValid
	
	if !certValid {
		result.SpoofingDetected = true
		result.Errors = append(result.Errors, "Certificate Error (Spoofed IP): "+tlsErr.Error())
	}

	return result
}



// EN: verifyTLS establishes a connection and verifies the certificate
// RU: verifyTLS устанавливает соединение и проверяет сертификат
func verifyTLS(ip, hostname string) (bool, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 3*time.Second)
	if err != nil {
		return false, fmt.Errorf("connection timeout/error: %v", err)
	}
	defer conn.Close()

	config := &tls.Config{
		ServerName: hostname, // EN: Ensure server provides valid certificate for the target domain
	}
	tlsConn := tls.Client(conn, config)
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	
	err = tlsConn.Handshake()
	if err != nil {
		return false, err
	}
	return true, nil
}
