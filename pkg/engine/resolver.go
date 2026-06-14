package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// dohEndpoint хранит URL и pre-resolved IP DoH-сервера.
// IP хардкодятся чтобы полностью избежать зависимости от системного DNS.
type dohEndpoint struct {
	URL string // полный URL для запроса
	IP  string // pre-resolved IP, не требует DNS-резолва
	SNI string // Server Name Indication для TLS handshake
}

// EN: DoH endpoints with hardcoded IPs to avoid system DNS dependency.
// RU: DoH эндпоинты с хардкодными IP, чтобы избежать зависимости от системного DNS.
// RU: Критично для мобильных VPN-клиентов где net.LookupHost создаёт петлю.
// RU: IP-адреса Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9) стабильны годами.
var dohEndpoints = []dohEndpoint{
	{
		URL: "https://cloudflare-dns.com/dns-query",
		IP:  "1.1.1.1",
		SNI: "cloudflare-dns.com",
	},
	{
		URL: "https://dns.google/resolve",
		IP:  "8.8.8.8",
		SNI: "dns.google",
	},
	{
		URL: "https://dns.quad9.net/dns-query",
		IP:  "9.9.9.9",
		SNI: "dns.quad9.net",
	},
}

// makeBootstrapClient создаёт HTTP-клиент с кастомным транспортом.
// DialContext игнорирует addr (hostname:port) из URL и подключается
// напрямую к hardcoded IP, минуя системный DNS полностью.
// TLS handshake при этом выполняется с правильным SNI для валидации сертификата.
func makeBootstrapClient(ep dohEndpoint) *http.Client {
	ip, port, err := net.SplitHostPort(ep.IP)
	if err != nil {
		ip = ep.IP
		port = "443"
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// RU: addr (второй аргумент) игнорируется — подключаемся к IP напрямую.
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
			TLSClientConfig: &tls.Config{
				ServerName:         ep.SNI, // TLS сертификат проверяется по имени, не по IP
				InsecureSkipVerify: ep.SNI == "localhost", // Только для локальных тестов
			},
		},
	}
}

// EN: GetTrustedDoH requests IPs via multiple DoH providers, bypassing system DNS.
// RU: GetTrustedDoH запрашивает IP через пул DoH серверов, минуя системный DNS.
// RU: Использует race-to-first паттерн: первый успешный ответ отменяет остальные.
func GetTrustedDoH(ctx context.Context, domain string) ([]string, error) {
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultChan := make(chan []string, 1)
	var wg sync.WaitGroup

	for _, ep := range dohEndpoints {
		wg.Add(1)
		go func(endpoint dohEndpoint) {
			defer wg.Done()

			client := makeBootstrapClient(endpoint)
			fullURL := fmt.Sprintf("%s?name=%s&type=A", endpoint.URL, domain)

			req, err := http.NewRequestWithContext(cancelCtx, "GET", fullURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/dns-json")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}

			var data struct {
				Status int `json:"Status"`
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				return
			}
			if data.Status != 0 { // 0 = NOERROR по RFC 8484
				return
			}

			var ips []string
			for _, ans := range data.Answer {
				if ans.Type == 1 { // A-запись
					ips = append(ips, ans.Data)
				}
			}

			if len(ips) > 0 {
				select {
				case resultChan <- ips:
				default:
				}
				cancel() // отменяем остальные горутины
			}
		}(ep)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	select {
	case ips, ok := <-resultChan:
		if ok {
			return ips, nil
		}
		return nil, fmt.Errorf("all DoH providers failed")
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled")
	}
}

// EN: CleanIPPool contains trusted public IPs that shouldn't be blocked by default.
// RU: Пул доверенных публичных IP (Cloudflare, Google, Yandex, Quad9).
var CleanIPPool = []string{
	"1.1.1.1",   // Cloudflare
	"8.8.8.8",   // Google
	"77.88.8.8", // Yandex
	"9.9.9.9",   // Quad9
}

// EN: GetCleanIP finds the first reachable clean IP to avoid false positives if Cloudflare is blocked.
// RU: GetCleanIP находит первый доступный IP из пула, чтобы избежать ложных срабатываний при блоке 1.1.1.1.
func GetCleanIP(ctx context.Context) string {
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ipChan := make(chan string, 1)
	var wg sync.WaitGroup

	for _, ip := range CleanIPPool {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			var dialer net.Dialer
			conn, err := dialer.DialContext(cancelCtx, "tcp", net.JoinHostPort(targetIP, "443"))
			if err == nil {
				conn.Close()
				select {
				case ipChan <- targetIP:
				default:
				}
				cancel() // EN: Cancel others immediately
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(ipChan)
	}()

	select {
	case activeIP, ok := <-ipChan:
		if ok {
			return activeIP
		}
		return "1.1.1.1"
	case <-ctx.Done():
		return "1.1.1.1"
	}
}
