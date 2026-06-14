package mobile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

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
