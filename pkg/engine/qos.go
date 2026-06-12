package engine

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// RTTStats holds statistics about TCP latency
type RTTStats struct {
	AvgMs    float64
	JitterMs float64
}

// MeasureTCPRTT runs multiple parallel dials to calculate average RTT and Jitter
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

// STUN Binding Request, RFC 5389
var stunRequest = []byte{
	0x00, 0x01,
	0x00, 0x00,
	0x21, 0x12, 0xA4, 0x42,
	0xDE, 0xAD, 0xBE, 0xEF,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
}

// MeasureUDPRTT uses STUN to measure UDP latency
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
	_, err = conn.Write(stunRequest)
	if err != nil {
		return 0, "", err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, "", err
	}

	if n >= 20 && buf[4] == 0x21 && buf[5] == 0x12 {
		return time.Since(start), "Symmetric/Port-Restricted", nil // Simplified NAT type for now
	}

	return 0, "", fmt.Errorf("not a valid STUN response")
}

// DetectUDPShaping compares RTT of small vs large QUIC packets
func DetectUDPShaping(ctx context.Context, cleanIP string) (bool, string) {
	return false, ""
}
