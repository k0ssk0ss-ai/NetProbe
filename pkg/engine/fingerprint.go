package engine

import (
	"context"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// fingerprintProfile pairs a human-readable label with a uTLS ClientHello template.
// The uTLS profile determines the *shape* of the ClientHello (its JA3/JA4), which is
// what fingerprint-based DPI blocks — independent of the VLESS/Reality credentials.
type fingerprintProfile struct {
	Name  string
	Hello utls.ClientHelloID
}

// fingerprintProfiles is the set probed by the Survivability Matrix. These cover the
// browser fingerprints a censor is most likely to allow/deny on RU (TSPU) paths, plus
// a randomized baseline as an evasion reference.
// Only stable, statically-settable browser profiles. "randomized" was dropped: its
// non-PASS results are ambiguous (server alerts vs. censorship) and clients configure a
// concrete fingerprint, not a per-connection random one. Easily re-added if needed.
var fingerprintProfiles = []fingerprintProfile{
	{"chrome", utls.HelloChrome_Auto},
	{"firefox", utls.HelloFirefox_Auto},
	{"safari", utls.HelloSafari_Auto},
	{"ios", utls.HelloIOS_Auto},
	{"edge", utls.HelloEdge_Auto},
}

// destProbeTimeout caps a single destination-facing TLS probe. A working handshake
// completes well under this; a silent blackhole never completes, so there is no point
// waiting the full scan deadline (~5s) on it. Bounds per-domain scan time on blocked hosts.
const destProbeTimeout = 2 * time.Second

// destProbeCtx returns a context bounded by destProbeTimeout, never exceeding the parent
// deadline (context.WithTimeout already takes the earlier of the two).
func destProbeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, destProbeTimeout)
}

// CheckFingerprints runs the Survivability Matrix: it sends each browser ClientHello
// fingerprint toward targetIP:443 with the given SNI and reports which ones survive the
// current network path. This automates the manual "switch chrome→firefox until it
// connects" debugging that motivated Vector A. See ROADMAP.md §2.
//
// All profiles are probed concurrently, so the whole matrix costs about as long as the
// single slowest handshake, bounded by the ctx deadline ("optimality and speed").
func CheckFingerprints(ctx context.Context, targetIP, sni string) []FingerprintResult {
	results := make([]FingerprintResult, len(fingerprintProfiles))
	var wg sync.WaitGroup
	for i, p := range fingerprintProfiles {
		wg.Add(1)
		go func(idx int, prof fingerprintProfile) {
			defer wg.Done()
			results[idx] = probeFingerprint(ctx, targetIP, sni, prof)
		}(i, p)
	}
	wg.Wait()
	return results
}

// probeFingerprint attempts a single uTLS handshake and classifies the outcome.
//
// InsecureSkipVerify is intentional: we are testing whether the *ClientHello* survives
// DPI, not whether the certificate is valid. Reaching the end of the handshake means the
// fingerprint passed; an injected RST/EOF means it was blocked; a timeout means a silent
// blackhole. A plain TLS alert from the server is not censorship and maps to OTHER.
//
// TODO(phase1): populate JA3/JA4 from the emitted ClientHello for shareable telemetry
// (Vector B). The PASS/RST/BLACKHOLE verdict — which is all Vector A needs — is complete.
func probeFingerprint(ctx context.Context, targetIP, sni string, p fingerprintProfile) FingerprintResult {
	res := FingerprintResult{Profile: p.Name}

	pctx, cancel := destProbeCtx(ctx)
	defer cancel()

	start := time.Now()

	var dialer net.Dialer
	conn, err := dialer.DialContext(pctx, "tcp", net.JoinHostPort(targetIP, "443"))
	if err != nil {
		res.Verdict = classifyFingerprintErr(err)
		res.RTTMs = elapsedMs(start)
		return res
	}
	defer conn.Close()

	if deadline, ok := pctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, p.Hello)
	defer uconn.Close()

	// EN: Build the ClientHello first so we fingerprint (JA3/JA4) exactly what gets sent.
	if buildErr := uconn.BuildHandshakeState(); buildErr == nil {
		res.JA3 = computeJA3(uconn.HandshakeState.Hello)
		res.JA4 = computeJA4(uconn.HandshakeState.Hello)
	}

	err = uconn.HandshakeContext(pctx)
	res.RTTMs = elapsedMs(start)
	if err == nil {
		res.Verdict = FPVerdictPass
		return res
	}
	res.Verdict = classifyFingerprintErr(err)
	return res
}

// classifyFingerprintErr maps a handshake/dial error to a survivability verdict.
func classifyFingerprintErr(err error) string {
	e := strings.ToLower(err.Error())
	switch {
	case strings.Contains(e, "reset by peer"),
		strings.Contains(e, "forcibly closed"), // Windows WSAECONNRESET wording
		strings.Contains(e, "10054"),
		strings.Contains(e, "eof"):
		return FPVerdictRST
	case strings.Contains(e, "timeout"),
		strings.Contains(e, "deadline exceeded"):
		return FPVerdictBlackhole
	default:
		// TLS alert, refused connection, or other non-censorship network error.
		return FPVerdictOther
	}
}

// elapsedMs returns milliseconds since start, rounded to 2 decimals.
func elapsedMs(start time.Time) float64 {
	return math.Round(float64(time.Since(start).Microseconds())/1000.0*100) / 100
}
