package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// EN: CheckDPI performs active DPI evasion heuristics
// RU: CheckDPI выполняет активные эвристики для обнаружения DPI
func CheckDPI(ctx context.Context, cleanIP string, bannedSNI string) DPIResult {
	result := DPIResult{
		SNIBlocked:  false,
		HTTPBlocked: false,
		Errors:      []string{},
	}

	// EN: 1. TLS SNI Test
	// RU: 1. Тест на SNI (Server Name Indication)
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cleanIP, "443"))
	if err != nil {
		result.Errors = append(result.Errors, "DPI TLS connect error: "+err.Error())
	} else {
		defer conn.Close()
		config := &tls.Config{
			ServerName:         bannedSNI, // Inject banned domain
			InsecureSkipVerify: true,
		}

		sendTime := time.Now()
		tlsConn := tls.Client(conn, config)
		defer tlsConn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			tlsConn.SetDeadline(deadline)
		}

		err = tlsConn.Handshake()
		rstDelay := time.Since(sendTime)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "reset by peer") || strings.Contains(errStr, "10054") || strings.Contains(errStr, "EOF") {
				result.SNIBlocked = true
				result.BlockMethod = "TCP RST"
				if rstDelay < 500*time.Millisecond {
					result.LikelyDPIInjected = true
				}
			} else if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "deadline exceeded") {
				result.SNIBlocked = true
				result.BlockMethod = "Blackhole"
			} else {
				result.Errors = append(result.Errors, "TLS Error: "+errStr)
			}
		}
	}

	// EN: 2. HTTP Host Header Test
	// RU: 2. Тест HTTP Host Header
	// EN: Sends an unencrypted HTTP request. If ISP reads HTTP headers, it will block it.
	// RU: Отправляет нешифрованный HTTP запрос. Если провайдер читает заголовки, он заблокирует его.
	// EN: For HTTP test we always use 1.1.1.1 because its raw HTTP 80 response is known (301, 400, 403).
	// RU: Для HTTP теста всегда используем 1.1.1.1, так как его ответ на 80 порту известен.
	httpTarget := "1.1.1.1"
	connHTTP, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(httpTarget, "80"))
	if err == nil {
		defer connHTTP.Close()
		if deadline, ok := ctx.Deadline(); ok {
			connHTTP.SetDeadline(deadline)
		}
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", bannedSNI)
		_, err = connHTTP.Write([]byte(req))
		if err != nil {
			if strings.Contains(err.Error(), "reset by peer") || strings.Contains(err.Error(), "10054") {
				result.HTTPBlocked = true
				if result.BlockMethod == "" {
					result.BlockMethod = "TCP RST (HTTP)"
				}
			} else {
				result.Errors = append(result.Errors, "HTTP Write Error: "+err.Error())
			}
			// EN: Continue to return result, no need to read since write failed
			return result
		}

		// EN: Read up to 4KB of the response to capture headers and block page body
		// RU: Читаем до 4 КБ ответа, чтобы захватить заголовки и тело страницы-заглушки
		respBuf, err := io.ReadAll(io.LimitReader(connHTTP, 4096))
		respStr := string(respBuf)

		if err != nil && len(respStr) == 0 {
			if strings.Contains(err.Error(), "reset by peer") || strings.Contains(err.Error(), "10054") || strings.Contains(err.Error(), "EOF") {
				result.HTTPBlocked = true
				if result.BlockMethod == "" {
					result.BlockMethod = "TCP RST (HTTP Read)"
				}
			}
		} else if len(respStr) > 0 {
			// EN: Check for known Russian ISP block pages
			lowerResp := strings.ToLower(respStr)
			if strings.Contains(lowerResp, "warning.rt.ru") {
				result.HTTPBlocked = true
				result.BlockMethod = "HTTP Inject (Rostelecom Blockpage)"
			} else if strings.Contains(lowerResp, "mts.ru") && strings.Contains(lowerResp, "block") {
				result.HTTPBlocked = true
				result.BlockMethod = "HTTP Inject (MTS Blockpage)"
			} else if strings.Contains(lowerResp, "e-gorod.ru") {
				result.HTTPBlocked = true
				result.BlockMethod = "HTTP Inject (Er-Telecom/Dom.ru Blockpage)"
			} else if strings.Contains(lowerResp, "beeline.ru") && strings.Contains(lowerResp, "block") {
				result.HTTPBlocked = true
				result.BlockMethod = "HTTP Inject (Beeline Blockpage)"
			} else if strings.Contains(lowerResp, "block.gossopka.ru") {
				result.HTTPBlocked = true
				result.BlockMethod = "HTTP Inject (Gov TSPU Blockpage)"
			} else {
				// EN: Fallback to basic status line check
				firstLine := strings.SplitN(respStr, "\n", 2)[0]
				if !strings.Contains(firstLine, "301") && !strings.Contains(firstLine, "302") && !strings.Contains(firstLine, "400") && !strings.Contains(firstLine, "403") {
					result.HTTPBlocked = true
					result.BlockMethod = "HTTP Redirect/Inject: " + strings.TrimSpace(firstLine)
				}
			}
		}
	}

	if !result.SNIBlocked && !result.HTTPBlocked {
		result.Errors = append(result.Errors, "[Clean] No DPI interference detected.")
	}

	return result
}
