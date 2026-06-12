package engine

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// EN: CheckDPI tests for DPI interference by checking SNI filtering and HTTP Host filtering.
// RU: CheckDPI тестирует DPI, проверяя SNI фильтрацию и HTTP Host фильтрацию.
func CheckDPI(cleanIP string, bannedSNI string) DPIResult {
	result := DPIResult{
		SNIBlocked:  false,
		HTTPBlocked: false,
		Errors:      []string{},
	}

	// EN: 1. SNI Test (Deep Packet Inspection TLS)
	// RU: 1. Тест SNI (Глубокий анализ TLS пакетов)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(cleanIP, "443"))
	if err == nil {
		defer conn.Close()
		config := &tls.Config{
			ServerName:         bannedSNI,
			InsecureSkipVerify: true,
		}
		tlsConn := tls.Client(conn, config)
		tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
		err = tlsConn.Handshake()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "reset by peer") || strings.Contains(errStr, "10054") || strings.Contains(errStr, "EOF") {
				result.SNIBlocked = true
				result.BlockMethod = "TCP RST"
			} else if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "deadline exceeded") {
				result.SNIBlocked = true
				result.BlockMethod = "Blackhole"
			} else {
				result.Errors = append(result.Errors, "TLS Error: "+errStr)
			}
		}
	} else {
		result.Errors = append(result.Errors, "SNI Dial Error: "+err.Error())
	}

	// EN: 2. HTTP Host Header Test
	// RU: 2. Тест HTTP Host Header
	// EN: Sends an unencrypted HTTP request. If ISP reads HTTP headers, it will block it.
	// RU: Отправляет нешифрованный HTTP запрос. Если провайдер читает заголовки, он заблокирует его.
	httpConn, err := dialer.Dial("tcp", net.JoinHostPort(cleanIP, "80"))
	if err == nil {
		defer httpConn.Close()
		httpConn.SetDeadline(time.Now().Add(3 * time.Second))
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", bannedSNI)
		_, err = httpConn.Write([]byte(req))
		if err != nil {
			if strings.Contains(err.Error(), "reset by peer") || strings.Contains(err.Error(), "10054") {
				result.HTTPBlocked = true
				if result.BlockMethod == "" {
					result.BlockMethod = "TCP RST (HTTP)"
				}
			}
		} else {
			reader := bufio.NewReader(httpConn)
			respLine, err := reader.ReadString('\n')
			if err != nil {
				if strings.Contains(err.Error(), "reset by peer") || strings.Contains(err.Error(), "10054") || strings.Contains(err.Error(), "EOF") {
					result.HTTPBlocked = true
					if result.BlockMethod == "" {
						result.BlockMethod = "TCP RST (HTTP Read)"
					}
				}
			} else {
				// EN: Cloudflare (1.1.1.1) on port 80 always returns 301, 400, or 403.
				// RU: Cloudflare (1.1.1.1) на 80 порту всегда дает 301, 400 или 403.
				// EN: If an ISP intercepts and injects a block page, we will get 200 OK or a different redirect.
				// RU: Если провайдер подменяет пакет на страницу-заглушку, ответ будет другим.
				if !strings.Contains(respLine, "301") && !strings.Contains(respLine, "400") && !strings.Contains(respLine, "403") {
					result.HTTPBlocked = true
					result.BlockMethod = "HTTP Redirect/Inject: " + strings.TrimSpace(respLine)
				}
			}
		}
	}

	if !result.SNIBlocked && !result.HTTPBlocked {
		result.Errors = append(result.Errors, "[Clean] No DPI interference detected.")
	}

	return result
}
