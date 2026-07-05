// Package adapter auto-detects the client config format (sing-box vs Xray) and produces
// neutral engine.OutboundCandidate values for the decision engine.
package adapter

import (
	"github.com/k0ssk0ss-ai/netprobe/pkg/adapter/singbox"
	"github.com/k0ssk0ss-ai/netprobe/pkg/adapter/xray"
	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

// Parse tries sing-box first, then Xray. sing-box keys outbounds by "type" and Xray by
// "protocol", so a sing-box parse of an Xray config yields zero candidates (no error) —
// which triggers the Xray fallback.
func Parse(data []byte) ([]engine.OutboundCandidate, error) {
	if c, err := singbox.Parse(data); err == nil && len(c) > 0 {
		return c, nil
	}
	return xray.Parse(data)
}
