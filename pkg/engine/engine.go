package engine

import (
	"context"
	"sync"
	"time"
)

// RunEngineScans executes all network checks concurrently using goroutines
// Публичная функция — используется из cmd/probe и lib/mobile.
func RunEngineScans(ctx context.Context, target string) ProbeReport {
	report := ProbeReport{
		Timestamp:  time.Now(),
		TargetHost: target,
	}

	var transportRes TransportResult
	var dpiRes DPIResult
	var dnsRes DNSResult

	var wg sync.WaitGroup
	wg.Add(3)

	// EN: Resolve a trusted clean IP first to avoid false positives
	cleanIP := GetCleanIP(ctx)

	// EN: Run 3 independent scanners in parallel
	go func() {
		defer wg.Done()
		transportRes = CheckTransport(ctx, cleanIP)
	}()

	go func() {
		defer wg.Done()
		dpiRes = CheckDPI(ctx, cleanIP, target)
	}()

	go func() {
		defer wg.Done()
		dnsRes = CheckDNS(ctx, cleanIP, target)
	}()

	// EN: Wait for the longest test to complete
	wg.Wait()

	report.Results.Transport = transportRes
	report.Results.DPI = dpiRes
	report.Results.DNS = dnsRes

	// EN: Strategy engine appends recommendations to the report
	AnalyzeResults(&report)

	return report
}
