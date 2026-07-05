package engine

import (
	"context"
	"strings"
	"sync"
)

// appEndpoint is one critical secondary endpoint of an app.
type appEndpoint struct {
	Host string
	Role string
}

// appEndpoints maps a primary domain to the secondary endpoints an app actually needs
// to function. Probing only the landing domain gives false "clean" readings (e.g.
// discord.com loads via CDN while gateway/voice are blocked). See ROADMAP.md.
var appEndpoints = map[string][]appEndpoint{
	"discord.com": {
		{Host: "gateway.discord.gg", Role: "gateway"}, // WebSocket — required for the app to connect
		{Host: "cdn.discordapp.com", Role: "cdn"},     // media/attachments
	},
}

// CheckEndpoints probes the critical secondary endpoints of a known app for TLS
// reachability against their REAL IPs (resolved via DoH). Returns nil for targets with
// no known app profile. Voice (UDP to dynamic IPs) is not covered by a generic TLS probe.
func CheckEndpoints(ctx context.Context, target string) []EndpointResult {
	eps, ok := appEndpoints[strings.ToLower(target)]
	if !ok {
		return nil
	}

	results := make([]EndpointResult, len(eps))
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func(idx int, e appEndpoint) {
			defer wg.Done()
			results[idx] = probeEndpoint(ctx, e)
		}(i, ep)
	}
	wg.Wait()
	return results
}

func probeEndpoint(ctx context.Context, ep appEndpoint) EndpointResult {
	res := EndpointResult{Host: ep.Host, Role: ep.Role}

	ips, err := GetTrustedDoH(ctx, ep.Host)
	if err != nil || len(ips) == 0 {
		res.BlockMethod = "DNS resolution failed"
		return res
	}

	ok, tlsErr := verifyTLS(ctx, ips[0], ep.Host)
	if ok {
		res.Reachable = true
		return res
	}
	res.BlockMethod = classifyFingerprintErr(tlsErr)
	return res
}
