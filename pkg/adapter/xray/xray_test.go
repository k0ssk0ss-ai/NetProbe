package xray

import "testing"

const sampleConfig = `{
  "outbounds": [
    {
      "protocol": "vless",
      "tag": "reality-out",
      "settings": {
        "vnext": [{
          "address": "1.2.3.4",
          "port": 443,
          "users": [{ "id": "deadbeef", "flow": "xtls-rprx-vision", "encryption": "none" }]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": { "serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "PBK", "shortId": "ab12" }
      }
    },
    {
      "protocol": "trojan",
      "tag": "trojan-out",
      "settings": { "servers": [{ "address": "5.6.7.8", "port": 8443, "password": "x" }] },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": { "serverName": "bing.com", "fingerprint": "firefox" }
      }
    },
    { "protocol": "freedom", "tag": "direct" }
  ]
}`

func TestParse_MapsXrayFields(t *testing.T) {
	cands, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("got %d candidates, want 2 (freedom skipped)", len(cands))
	}

	r := cands[0]
	if r.ID != "reality-out" || r.Protocol != "vless" || r.Security != "reality" {
		t.Errorf("reality candidate: id=%q proto=%q sec=%q", r.ID, r.Protocol, r.Security)
	}
	if r.Host != "1.2.3.4" || r.Port != 443 {
		t.Errorf("reality endpoint: %s:%d", r.Host, r.Port)
	}
	if r.SNI != "www.microsoft.com" || r.Fingerprint != "chrome" {
		t.Errorf("reality sni/fp: %q/%q", r.SNI, r.Fingerprint)
	}

	tr := cands[1]
	if tr.Protocol != "trojan" || tr.Security != "tls" || tr.Transport != "ws" {
		t.Errorf("trojan: proto=%q sec=%q transport=%q", tr.Protocol, tr.Security, tr.Transport)
	}
	if tr.Host != "5.6.7.8" || tr.Port != 8443 {
		t.Errorf("trojan endpoint: %s:%d", tr.Host, tr.Port)
	}
	if !tr.CDNFronted {
		t.Error("trojan over ws should be CDN-frontable")
	}
	if tr.Fingerprint != "firefox" {
		t.Errorf("trojan fp = %q, want firefox", tr.Fingerprint)
	}
}

func TestParse_RawNetworkAliasesTCP(t *testing.T) {
	single := `{"protocol":"vless","tag":"v","settings":{"vnext":[{"address":"9.9.9.9","port":443}]},"streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"a.com"}}}`
	cands, err := Parse([]byte(single))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cands) != 1 || cands[0].Transport != "tcp" {
		t.Fatalf("expected raw→tcp, got %+v", cands)
	}
}
