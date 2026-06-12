package engine

import (
	"context"
	"math"
	"net"
)

// EN: CheckTransport checks basic TCP and UDP connectivity
// RU: CheckTransport проверяет базовую связность по TCP и UDP
func CheckTransport(ctx context.Context, cleanIP string) TransportResult {
	result := TransportResult{
		TCP443Open:  false,
		UDP53Works:  false,
		UDP443Works: false,
		Errors:      []string{},
	}

	// EN: 1. TCP 443 Test (HTTPS) and QoS
	// RU: 1. Проверка TCP 443 (HTTPS) и QoS
	var dialer net.Dialer
	connTCP, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cleanIP, "443"))
	if err == nil {
		result.TCP443Open = true
		connTCP.Close()

		// Run QoS metric for TCP
		stats := MeasureTCPRTT(ctx, cleanIP, "443", 3)
		result.TCPRTTAvgMs = stats.AvgMs
		result.TCPJitterMs = stats.JitterMs
	} else {
		result.Errors = append(result.Errors, "TCP Error: "+err.Error())
	}

	// EN: 2. UDP 53 Test (DNS)
	// RU: 2. Проверка UDP 53 (DNS)
	// EN: We send a raw DNS packet to cleanIP to verify UDP traffic is not dropped
	// RU: Отправляем сырой пакет на cleanIP, чтобы проверить, проходит ли UDP трафик
	connUDP, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(cleanIP, "53"))
	if err == nil {
		if deadline, ok := ctx.Deadline(); ok {
			connUDP.SetDeadline(deadline)
		}
		// EN: Raw DNS query for google.com (A record)
		// RU: Сырой DNS запрос для google.com (A-запись)
		dnsQuery := []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
			0x00, 0x01, 0x00, 0x01,
		}
		_, err = connUDP.Write(dnsQuery)
		if err == nil {
			buf := make([]byte, 512)
			n, err := connUDP.Read(buf)
			if err == nil && n > 0 {
				result.UDP53Works = true
			} else {
				result.Errors = append(result.Errors, "UDP Read Error: "+err.Error())
			}
		} else {
			result.Errors = append(result.Errors, "UDP Write Error: "+err.Error())
		}
		connUDP.Close()
	} else {
		result.Errors = append(result.Errors, "UDP Dial Error: "+err.Error())
	}

	// EN: 3. UDP 443 Test (QUIC / Hysteria2)
	// RU: 3. Проверка UDP 443 (QUIC / Hysteria2)
	// EN: Send a QUIC Initial packet (Long Header) with dummy version to force Version Negotiation
	// RU: Отправляем QUIC Initial пакет с фейковой версией, чтобы вызвать Version Negotiation
	connQUIC, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(cleanIP, "443"))
	if err == nil {
		payload := make([]byte, 1200) // EN: Padding is required by QUIC spec
		payload[0] = 0xc0
		payload[1] = 0x0a
		payload[2] = 0x0a
		payload[3] = 0x0a
		payload[4] = 0x0a
		payload[5] = 0x08
		payload[6] = 0x00
		for i := 0; i < 8; i++ {
			payload[7+i] = byte(i)
		}

		if deadline, ok := ctx.Deadline(); ok {
			connQUIC.SetDeadline(deadline)
		}
		_, err = connQUIC.Write(payload)
		if err == nil {
			buf := make([]byte, 1500)
			n, err := connQUIC.Read(buf)
			if err == nil && n > 0 {
				result.UDP443Works = true
			} else {
				result.Errors = append(result.Errors, "QUIC Read Error: "+err.Error())
			}
		} else {
			result.Errors = append(result.Errors, "QUIC Write Error: "+err.Error())
		}
		connQUIC.Close()
	} else {
		result.Errors = append(result.Errors, "QUIC Dial Error: "+err.Error())
	}

	// 4. Measure UDP RTT via STUN
	udpRtt, natType, err := MeasureUDPRTT(ctx, "stun.l.google.com:19302")
	if err == nil {
		result.UDPRTTMs = math.Round(float64(udpRtt.Milliseconds())*100) / 100
		result.NATType = natType
	}

	return result
}
