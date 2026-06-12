package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// EN: CleanIPPool contains trusted public IPs that shouldn't be blocked by default.
// RU: Пул доверенных публичных IP (Cloudflare, Google, Yandex, Quad9).
var CleanIPPool = []string{
	"1.1.1.1",   // Cloudflare
	"8.8.8.8",   // Google
	"77.88.8.8", // Yandex
	"9.9.9.9",   // Quad9
}

// EN: DoHPool contains trusted DoH endpoints.
// RU: Пул доверенных DoH серверов.
var DoHPool = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
	"https://dns.quad9.net/dns-query",
}

// EN: GetCleanIP finds the first reachable clean IP to avoid false positives if Cloudflare is blocked.
// RU: GetCleanIP находит первый доступный IP из пула, чтобы избежать ложных срабатываний при блоке 1.1.1.1.
func GetCleanIP(ctx context.Context) string {
	ipChan := make(chan string, len(CleanIPPool))

	for _, ip := range CleanIPPool {
		go func(targetIP string) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(targetIP, "443"))
			if err == nil {
				conn.Close()
				ipChan <- targetIP
			}
		}(ip)
	}

	select {
	case activeIP := <-ipChan:
		return activeIP
	case <-ctx.Done():
		return "1.1.1.1"
	}
}

// EN: GetTrustedDoH requests IP via multiple DoH providers to bypass blockings.
// RU: GetTrustedDoH запрашивает IP через пул DoH серверов.
func GetTrustedDoH(ctx context.Context, domain string) ([]string, error) {
	resultChan := make(chan []string, len(DoHPool))

	for _, url := range DoHPool {
		go func(providerUrl string) {
			client := &http.Client{}
			fullUrl := fmt.Sprintf("%s?name=%s&type=A", providerUrl, domain)
			req, _ := http.NewRequestWithContext(ctx, "GET", fullUrl, nil)
			req.Header.Set("Accept", "application/dns-json")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			var data struct {
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				return
			}

			var ips []string
			for _, ans := range data.Answer {
				if ans.Type == 1 {
					ips = append(ips, ans.Data)
				}
			}

			if len(ips) > 0 {
				resultChan <- ips
			}
		}(url)
	}

	select {
	case ips := <-resultChan:
		return ips, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("all DoH providers failed or context cancelled")
	}
}
