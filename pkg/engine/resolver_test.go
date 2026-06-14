package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestGetTrustedDoH_BypassesSystemDNS проверяет что GetTrustedDoH
// использует hardcoded IP и не зависит от системного DNS.
func TestGetTrustedDoH_BypassesSystemDNS(t *testing.T) {
	// Подменяем один из dohEndpoints на локальный mock-сервер
	mockResp := `{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		w.Write([]byte(mockResp))
	}))
	defer server.Close()

	// Подмена эндпоинта в тесте
	original := dohEndpoints
	u, _ := url.Parse(server.URL)
	dohEndpoints = []dohEndpoint{{
		URL: server.URL + "/dns-query",
		IP:  u.Host, // contains IP:Port
		SNI: "localhost",
	}}
	defer func() { dohEndpoints = original }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := GetTrustedDoH(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetTrustedDoH failed: %v", err)
	}
	if len(ips) == 0 || ips[0] != "1.2.3.4" {
		t.Fatalf("unexpected IPs: %v", ips)
	}
}
