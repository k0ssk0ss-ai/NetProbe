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
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now(),
		TargetHost:    target,
	}

	var transportRes TransportResult
	var dpiRes DPIResult
	var dnsRes DNSResult
	var fpMatrix []FingerprintResult
	var endpointRes []EndpointResult

	// EN: Resolve two IPs up front (in parallel):
	//   - cleanIP: a trusted reference for transport tests.
	//   - targetIP: the target's REAL IP via DoH (bypasses spoofing). The DPI and
	//     fingerprint probes must hit this, not a clean IP, or destination-aware
	//     blocking (RST on the real IP) is missed and reported as "clean".
	var cleanIP, targetIP string
	var pre sync.WaitGroup
	pre.Add(2)
	go func() {
		defer pre.Done()
		cleanIP = GetCleanIP(ctx)
	}()
	go func() {
		defer pre.Done()
		if ips, err := GetTrustedDoH(ctx, target); err == nil && len(ips) > 0 {
			targetIP = ips[0]
		}
	}()
	pre.Wait()
	if targetIP == "" {
		targetIP = cleanIP // degraded fallback if DoH resolution failed
	}

	var wg sync.WaitGroup
	wg.Add(5)

	// EN: Run independent scanners in parallel
	go func() {
		defer wg.Done()
		transportRes = CheckTransport(ctx, cleanIP)
	}()

	// EN: DPI SNI test hits the REAL target IP — catches destination-aware RST/blackhole
	go func() {
		defer wg.Done()
		dpiRes = CheckDPI(ctx, targetIP, target)
	}()

	go func() {
		defer wg.Done()
		dnsRes = CheckDNS(ctx, cleanIP, target)
	}()

	// EN: Survivability Matrix against the REAL target IP — which uTLS fingerprints
	// actually survive to the destination (accurate mode).
	go func() {
		defer wg.Done()
		fpMatrix = CheckFingerprints(ctx, targetIP, target)
	}()

	// EN: Secondary app endpoints (gateway/CDN) — "landing works" != "app works"
	go func() {
		defer wg.Done()
		endpointRes = CheckEndpoints(ctx, target)
	}()

	// EN: Wait for the longest test to complete
	wg.Wait()

	report.Results.Transport = transportRes
	report.Results.DPI = dpiRes
	report.Results.DNS = dnsRes
	report.FingerprintMatrix = fpMatrix
	report.Endpoints = endpointRes

	// EN: Strategy engine appends recommendations to the report
	AnalyzeResults(&report)

	// EN: Vector B seed — no-op unless an integrator opted in by setting engine.Sink.
	emitTelemetry(report)

	return report
}
