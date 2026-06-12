package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
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
func GetCleanIP() string {
	ipChan := make(chan string, len(CleanIPPool))

	for _, ip := range CleanIPPool {
		go func(targetIP string) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, "443"), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				ipChan <- targetIP
			}
		}(ip)
	}

	select {
	case activeIP := <-ipChan:
		return activeIP
	case <-time.After(550 * time.Millisecond):
		return "1.1.1.1"
	}
}

// EN: GetTrustedDoH requests IP via multiple DoH providers to bypass blockings.
// RU: GetTrustedDoH запрашивает IP через пул DoH серверов.
func GetTrustedDoH(domain string) ([]string, error) {
	client := &http.Client{Timeout: 3 * time.Second}

	for _, providerUrl := range DoHPool {
		url := fmt.Sprintf("%s?name=%s&type=A", providerUrl, domain)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue // Try next DoH provider
		}
		
		var data struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}

		err = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		
		if err != nil {
			continue
		}

		var ips []string
		for _, ans := range data.Answer {
			if ans.Type == 1 { // A record
				ips = append(ips, ans.Data)
			}
		}
		
		if len(ips) > 0 {
			return ips, nil
		}
	}

	return nil, fmt.Errorf("all DoH providers failed or blocked")
}
