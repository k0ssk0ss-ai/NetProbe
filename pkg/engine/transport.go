package engine

import (
	"context"
	"crypto/tls"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// EN: CheckTransport checks basic TCP and UDP connectivity
// RU: CheckTransport проверяет базовую связность по TCP и UDP
func CheckTransport(ctx context.Context, cleanIP string) TransportResult {
	var result TransportResult
	result.Errors = []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(5)

	// EN: 1. TCP 443 Test (HTTPS) and QoS
	go func() {
		defer wg.Done()
		var dialer net.Dialer
		connTCP, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cleanIP, "443"))
		if err == nil {
			mu.Lock()
			result.TCP443Open = true
			mu.Unlock()
			connTCP.Close()

			stats := MeasureTCPRTT(ctx, cleanIP, "443", 3)
			mu.Lock()
			result.TCPRTTAvgMs = stats.AvgMs
			result.TCPJitterMs = stats.JitterMs
			mu.Unlock()
		} else {
			mu.Lock()
			result.Errors = append(result.Errors, "TCP Dial Error: "+err.Error())
			mu.Unlock()
		}
	}()

	// EN: 2. UDP 53 Test
	go func() {
		defer wg.Done()
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
		r, _, err := c.Exchange(m, net.JoinHostPort(cleanIP, "53"))
		if err == nil && r != nil {
			mu.Lock()
			result.UDP53Works = true
			mu.Unlock()
		} else {
			mu.Lock()
			result.Errors = append(result.Errors, "UDP 53 Error: "+err.Error())
			mu.Unlock()
		}
	}()

	// EN: 3. UDP 443 Test (QUIC) — real handshake via quic-go library.
	// RU: 3. Тест UDP 443 (QUIC) — настоящий хэндшейк через библиотеку quic-go.
	// RU: Если хэндшейк дошёл до TLS-фазы (ошибка сертификата) — UDP открыт.
	// RU: Если connection timeout/refused — UDP заблокирован или зашейплен.
	go func() {
		defer wg.Done()

		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		}
		quicConf := &quic.Config{
			HandshakeIdleTimeout: 2 * time.Second,
		}

		dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
		defer dialCancel()

		conn, err := quic.DialAddr(dialCtx, "1.1.1.1:443", tlsConf, quicConf)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "tls") ||
				strings.Contains(errStr, "certificate") ||
				strings.Contains(errStr, "handshake") {
				mu.Lock()
				result.UDP443Works = true
				mu.Unlock()
			} else {
				mu.Lock()
				result.Errors = append(result.Errors, "QUIC Error: "+errStr)
				mu.Unlock()
			}
			return
		}
		conn.CloseWithError(0, "probe complete")
		mu.Lock()
		result.UDP443Works = true
		mu.Unlock()
	}()

	// EN: 4. Measure UDP RTT via STUN
	go func() {
		defer wg.Done()
		udpRtt, natType, err := MeasureUDPRTT(ctx, "stun.l.google.com:19302")
		if err == nil {
			mu.Lock()
			result.UDPRTTMs = math.Round(float64(udpRtt.Milliseconds())*100) / 100
			result.NATType = natType
			mu.Unlock()
		}
	}()

	// EN: 5. Detect UDP MTU Shaping
	go func() {
		defer wg.Done()
		isShaped, shapeReason := DetectUDPShaping(ctx, cleanIP)
		mu.Lock()
		result.IsUDPShaped = isShaped
		result.UDPShapingReason = shapeReason
		mu.Unlock()
	}()

	wg.Wait()
	return result
}
