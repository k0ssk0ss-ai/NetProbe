// Package singbox adapts sing-box outbound configuration into neutral
// engine.OutboundCandidate values for the decision engine (Vector A).
//
// It lives outside pkg/engine so the core never imports client-specific types:
// the dependency points core ← adapter, never the reverse. A parallel Xray adapter
// is the planned fast-follow. See ROADMAP.md §6.
package singbox

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

// sbOutbound mirrors the subset of a sing-box outbound object we need to build a
// candidate. Unknown fields are ignored by encoding/json.
type sbOutbound struct {
	Type       string     `json:"type"`
	Tag        string     `json:"tag"`
	Server     string     `json:"server"`
	ServerPort int        `json:"server_port"`
	TLS        *sbTLS     `json:"tls"`
	Transport  *sbTranspt `json:"transport"`
}

type sbTLS struct {
	Enabled    bool       `json:"enabled"`
	ServerName string     `json:"server_name"`
	UTLS       *sbUTLS    `json:"utls"`
	Reality    *sbReality `json:"reality"`
}

type sbUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type sbReality struct {
	Enabled bool `json:"enabled"`
}

type sbTranspt struct {
	Type string `json:"type"`
}

// config is a full sing-box config; we only care about outbounds.
type config struct {
	Outbounds []sbOutbound `json:"outbounds"`
}

// Parse accepts a full sing-box config ({"outbounds": [...]}), a bare JSON array of
// outbounds, or a single outbound object, and returns neutral candidates. Non-proxy
// outbounds (direct, block, dns, selector, urltest) are skipped.
func Parse(data []byte) ([]engine.OutboundCandidate, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty input")
	}

	var raw []sbOutbound
	switch trimmed[0] {
	case '{':
		// Either a full config or a single outbound.
		var cfg config
		if err := json.Unmarshal(data, &cfg); err == nil && len(cfg.Outbounds) > 0 {
			raw = cfg.Outbounds
		} else {
			var single sbOutbound
			if err := json.Unmarshal(data, &single); err != nil {
				return nil, fmt.Errorf("parse outbound object: %w", err)
			}
			raw = []sbOutbound{single}
		}
	case '[':
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse outbound array: %w", err)
		}
	default:
		return nil, fmt.Errorf("unexpected JSON (want object or array)")
	}

	var candidates []engine.OutboundCandidate
	for i, ob := range raw {
		if !isProxy(ob.Type) {
			continue
		}
		candidates = append(candidates, toCandidate(ob, i))
	}
	return candidates, nil
}

func isProxy(t string) bool {
	switch strings.ToLower(t) {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "wireguard", "shadowtls":
		return true
	}
	return false
}

func toCandidate(ob sbOutbound, idx int) engine.OutboundCandidate {
	c := engine.OutboundCandidate{
		ID:       fallbackID(ob.Tag, ob.Type, idx),
		Protocol: strings.ToLower(ob.Type),
		Host:     ob.Server,
		Port:     ob.ServerPort,
	}

	// Transport: QUIC-native protocols have no explicit transport block.
	switch {
	case ob.Transport != nil && ob.Transport.Type != "":
		c.Transport = strings.ToLower(ob.Transport.Type)
	case c.Protocol == "hysteria2" || c.Protocol == "hysteria" || c.Protocol == "tuic":
		c.Transport = "quic"
	default:
		c.Transport = "tcp"
	}

	// Security + SNI + fingerprint.
	if ob.TLS != nil && ob.TLS.Enabled {
		c.SNI = ob.TLS.ServerName
		if ob.TLS.Reality != nil && ob.TLS.Reality.Enabled {
			c.Security = "reality"
		} else {
			c.Security = "tls"
		}
		if ob.TLS.UTLS != nil && ob.TLS.UTLS.Enabled {
			c.Fingerprint = strings.ToLower(ob.TLS.UTLS.Fingerprint)
		}
	} else {
		c.Security = "none"
	}

	// CDN-frontable transports let the client swap the dial IP (dial_ip override).
	switch c.Transport {
	case "ws", "grpc", "http", "httpupgrade":
		c.CDNFronted = true
	}

	return c
}

func fallbackID(tag, typ string, idx int) string {
	if tag != "" {
		return tag
	}
	return fmt.Sprintf("%s-%d", strings.ToLower(typ), idx)
}
