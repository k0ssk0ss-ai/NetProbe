// Package xray adapts Xray-core outbound configuration into neutral
// engine.OutboundCandidate values for the decision engine (Vector A).
//
// Xray's shape differs from sing-box: the protocol is under "protocol", the server lives
// in settings.vnext/servers, and TLS/Reality/transport live in streamSettings. Like the
// sing-box adapter, this lives outside pkg/engine so the core imports no client types.
package xray

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

type xrayOutbound struct {
	Protocol       string        `json:"protocol"`
	Tag            string        `json:"tag"`
	Settings       *xraySettings `json:"settings"`
	StreamSettings *xrayStream   `json:"streamSettings"`
}

type xraySettings struct {
	Vnext   []xrayServer `json:"vnext"`   // vless, vmess
	Servers []xrayServer `json:"servers"` // trojan, shadowsocks
}

type xrayServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type xrayStream struct {
	Network         string       `json:"network"`
	Security        string       `json:"security"`
	TLSSettings     *xrayTLS     `json:"tlsSettings"`
	RealitySettings *xrayReality `json:"realitySettings"`
}

type xrayTLS struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
}

type xrayReality struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
}

type config struct {
	Outbounds []xrayOutbound `json:"outbounds"`
}

// Parse accepts a full Xray config ({"outbounds": [...]}), a bare array of outbounds, or a
// single outbound object, and returns neutral candidates. Non-proxy outbounds
// (freedom, blackhole, dns) are skipped.
func Parse(data []byte) ([]engine.OutboundCandidate, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty input")
	}

	var raw []xrayOutbound
	switch trimmed[0] {
	case '{':
		var cfg config
		if err := json.Unmarshal(data, &cfg); err == nil && len(cfg.Outbounds) > 0 {
			raw = cfg.Outbounds
		} else {
			var single xrayOutbound
			if err := json.Unmarshal(data, &single); err != nil {
				return nil, fmt.Errorf("parse outbound object: %w", err)
			}
			raw = []xrayOutbound{single}
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
		if !isProxy(ob.Protocol) {
			continue
		}
		candidates = append(candidates, toCandidate(ob, i))
	}
	return candidates, nil
}

func isProxy(p string) bool {
	switch strings.ToLower(p) {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "wireguard":
		return true
	}
	return false
}

func toCandidate(ob xrayOutbound, idx int) engine.OutboundCandidate {
	c := engine.OutboundCandidate{
		ID:       fallbackID(ob.Tag, ob.Protocol, idx),
		Protocol: strings.ToLower(ob.Protocol),
	}

	// Server endpoint: vnext (vless/vmess) or servers (trojan/shadowsocks).
	if ob.Settings != nil {
		var srv *xrayServer
		if len(ob.Settings.Vnext) > 0 {
			srv = &ob.Settings.Vnext[0]
		} else if len(ob.Settings.Servers) > 0 {
			srv = &ob.Settings.Servers[0]
		}
		if srv != nil {
			c.Host = srv.Address
			c.Port = srv.Port
		}
	}

	// Transport ("raw" is Xray's newer name for "tcp").
	c.Transport = "tcp"
	if ob.StreamSettings != nil && ob.StreamSettings.Network != "" {
		n := strings.ToLower(ob.StreamSettings.Network)
		if n == "raw" {
			n = "tcp"
		}
		c.Transport = n
	}

	// Security + SNI + fingerprint.
	c.Security = "none"
	if ob.StreamSettings != nil {
		sec := strings.ToLower(ob.StreamSettings.Security)
		switch {
		case sec == "reality" && ob.StreamSettings.RealitySettings != nil:
			c.Security = "reality"
			c.SNI = ob.StreamSettings.RealitySettings.ServerName
			c.Fingerprint = strings.ToLower(ob.StreamSettings.RealitySettings.Fingerprint)
		case (sec == "tls" || sec == "xtls") && ob.StreamSettings.TLSSettings != nil:
			c.Security = "tls"
			c.SNI = ob.StreamSettings.TLSSettings.ServerName
			c.Fingerprint = strings.ToLower(ob.StreamSettings.TLSSettings.Fingerprint)
		}
	}

	// CDN-frontable transports (Xray names: ws, grpc, http/h2, httpupgrade, xhttp/splithttp).
	switch c.Transport {
	case "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "splithttp":
		c.CDNFronted = true
	}

	return c
}

func fallbackID(tag, proto string, idx int) string {
	if tag != "" {
		return tag
	}
	return fmt.Sprintf("%s-%d", strings.ToLower(proto), idx)
}
