package mobile

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/k0ssk0ss-ai/netprobe/pkg/adapter"
	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

// defaultDonationDomains is the set scanned by a "donate a test" when the client passes none.
var defaultDonationDomains = []string{
	"youtube.com", "web.telegram.org", "discord.com", "instagram.com", "twitter.com",
}

// RunScan — основная точка входа для Android/iOS клиентов.
//
// Принимает: target — домен для проверки (например, "youtube.com").
// Возвращает: JSON-строку ProbeReport или {"error": "..."} при сбое.
//
// Таймаут: 3 секунды (оптимизирован для мобильных клиентов).
//
// Сборка Android: gomobile bind -target=android -androidapi=21 -o netprobe.aar ./lib/mobile
// Сборка iOS:     gomobile bind -target=ios -o NetProbe.xcframework ./lib/mobile
func RunScan(target string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	report := engine.RunEngineScans(ctx, target)

	b, err := json.Marshal(report)
	if err != nil {
		return `{"error": "serialization failed"}`
	}
	return string(b)
}

// DonatePreview — ШАГ 1 кнопки «пожертвовать тест».
//
// Принимает: domainsCSV — домены через запятую (пусто = дефолтный список).
// Возвращает: JSON-массив AnonReport — обезличенные результаты БЕЗ IP и идентификаторов.
// Ничего не отправляет: клиент показывает это превью пользователю. Отправка — только
// после явного подтверждения через DonateSend.
func DonatePreview(domainsCSV string) string {
	domains := defaultDonationDomains
	if s := strings.TrimSpace(domainsCSV); s != "" {
		domains = splitCSV(s)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	reports := engine.RunDonation(ctx, domains)
	b, err := json.Marshal(reports)
	if err != nil {
		return `{"error": "serialization failed"}`
	}
	return string(b)
}

// DonateSend — ШАГ 2: отправка подтверждённого превью на коллектор.
//
// Принимает: previewJSON — то, что вернул DonatePreview (пользователь согласился);
// endpoint — URL коллектора; bootstrapIP — hardcoded Cloudflare IP (обход блокировки
// домена); sni — hostname коллектора для TLS.
// Возвращает: {"ok":true,"count":N} или {"error":"..."}.
func DonateSend(previewJSON, endpoint, bootstrapIP, sni string) string {
	var reports []engine.AnonReport
	if err := json.Unmarshal([]byte(previewJSON), &reports); err != nil {
		return `{"error": "invalid preview json"}`
	}
	if len(reports) == 0 {
		return `{"error": "nothing to send"}`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sink := engine.NewHTTPSink(endpoint, bootstrapIP, sni)
	if err := sink.SendBatch(ctx, reports); err != nil {
		return `{"error": "` + err.Error() + `"}`
	}
	b, _ := json.Marshal(map[string]any{"ok": true, "count": len(reports)})
	return string(b)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// RunScanWithConfig — точка входа для Vector A (умный выбор конфига).
//
// Принимает: target — домен для диагностики; configJSON — sing-box конфиг клиента
// (полный конфиг, массив outbounds или один outbound).
// Возвращает: JSON ProbeReport с заполненным полем "decision" — какой outbound
// использовать и какие client-tunable параметры (fingerprint/port/sni/fragment/dial_ip)
// переопределить, чтобы соединение прошло сквозь DPI.
//
// Сборка та же, что и RunScan (gomobile bind ./lib/mobile).
func RunScanWithConfig(target string, configJSON string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	report := engine.RunEngineScans(ctx, target)

	if cands, err := adapter.Parse([]byte(configJSON)); err == nil && len(cands) > 0 {
		// Accurate mode — actively probe each candidate's own endpoint.
		actx, acancel := context.WithTimeout(context.Background(), 4*time.Second)
		report.Decision = engine.DecideOutboundActive(actx, report, cands)
		acancel()
	}

	b, err := json.Marshal(report)
	if err != nil {
		return `{"error": "serialization failed"}`
	}
	return string(b)
}
