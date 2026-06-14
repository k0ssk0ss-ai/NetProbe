package engine

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// RTTStats хранит статистику TCP-задержки.
type RTTStats struct {
	AvgMs    float64
	JitterMs float64
}

// MeasureTCPRTT — без изменений относительно v2.4.
func MeasureTCPRTT(ctx context.Context, host string, port string, samples int) RTTStats {
	results := make(chan time.Duration, samples)
	var wg sync.WaitGroup

	for i := 0; i < samples; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
			rtt := time.Since(start)
			if err == nil {
				conn.Close()
				results <- rtt
			}
		}()
	}
	wg.Wait()
	close(results)

	var durations []float64
	for d := range results {
		durations = append(durations, float64(d.Milliseconds()))
	}
	if len(durations) == 0 {
		return RTTStats{}
	}

	var sum float64
	for _, v := range durations {
		sum += v
	}
	mean := sum / float64(len(durations))

	var variance float64
	for _, v := range durations {
		diff := v - mean
		variance += diff * diff
	}

	return RTTStats{
		AvgMs:    math.Round(mean*100) / 100,
		JitterMs: math.Round(math.Sqrt(variance/float64(len(durations)))*100) / 100,
	}
}

// STUN Binding Request по RFC 5389.
var stunRequest = []byte{
	0x00, 0x01, 0x00, 0x00,
	0x21, 0x12, 0xA4, 0x42,
	0xDE, 0xAD, 0xBE, 0xEF,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
}

// MeasureUDPRTT использует STUN для измерения UDP-задержки. Без изменений.
func MeasureUDPRTT(ctx context.Context, stunServer string) (time.Duration, string, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", stunServer)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	start := time.Now()
	if _, err = conn.Write(stunRequest); err != nil {
		return 0, "", err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, "", err
	}

	if n >= 20 {
		msgType := uint16(buf[0])<<8 | uint16(buf[1])
		if msgType == 0x0101 && buf[4] == 0x21 && buf[5] == 0x12 {
			return time.Since(start), "Unknown", nil
		}
	}
	return 0, "", fmt.Errorf("not a valid STUN response")
}

// DetectUDPShaping — STUB для v2.5.
//
// EN: Previous implementation sent an invalid QUIC packet and always returned (false, "").
// EN: Full MTU/shaping detection via STUN ICMP is planned for v3.0.
// EN: Using an honest stub instead of silently broken code.
//
// RU: Предыдущая реализация отправляла невалидный QUIC пакет и всегда возвращала (false, "").
// RU: Это создавало ложное ощущение что UDP shaping отсутствует, хотя тест не работал.
// RU: Честный stub позволяет агрегатору краудсорсинга фильтровать эти записи как N/A.
// RU: Полноценная реализация через STUN ICMP MTU тест запланирована на v3.0.
func DetectUDPShaping(ctx context.Context, cleanIP string) (bool, string) {
	return false, "Not implemented in v2.5 (planned for v3.0: STUN ICMP MTU test)"
}
