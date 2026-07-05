package singbox

import "testing"

const sampleConfig = `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-out",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "deadbeef",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.microsoft.com",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": { "enabled": true, "public_key": "PBK", "short_id": "ab12" }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-out",
      "server": "5.6.7.8",
      "server_port": 443,
      "tls": { "enabled": true, "server_name": "bing.com" }
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "selector", "tag": "select" }
  ]
}`

func TestParse_SkipsNonProxyAndMapsFields(t *testing.T) {
	cands, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("got %d candidates, want 2 (direct/selector skipped)", len(cands))
	}

	reality := cands[0]
	if reality.ID != "reality-out" || reality.Protocol != "vless" {
		t.Errorf("candidate[0] id/proto = %q/%q", reality.ID, reality.Protocol)
	}
	if reality.Security != "reality" {
		t.Errorf("security = %q, want reality", reality.Security)
	}
	if reality.SNI != "www.microsoft.com" {
		t.Errorf("sni = %q", reality.SNI)
	}
	if reality.Fingerprint != "chrome" {
		t.Errorf("fingerprint = %q, want chrome", reality.Fingerprint)
	}
	if reality.Transport != "tcp" {
		t.Errorf("transport = %q, want tcp", reality.Transport)
	}
	if reality.Port != 443 {
		t.Errorf("port = %d, want 443", reality.Port)
	}

	hy2 := cands[1]
	if hy2.Protocol != "hysteria2" || hy2.Transport != "quic" {
		t.Errorf("hy2 proto/transport = %q/%q, want hysteria2/quic", hy2.Protocol, hy2.Transport)
	}
	if hy2.Security != "tls" {
		t.Errorf("hy2 security = %q, want tls", hy2.Security)
	}
}

func TestParse_SingleOutboundObject(t *testing.T) {
	single := `{"type":"trojan","tag":"t","server":"9.9.9.9","server_port":8443,"tls":{"enabled":true,"server_name":"a.com"}}`
	cands, err := Parse([]byte(single))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cands) != 1 || cands[0].Protocol != "trojan" || cands[0].Port != 8443 {
		t.Fatalf("unexpected candidates: %+v", cands)
	}
}

func TestParse_Array(t *testing.T) {
	arr := `[{"type":"shadowsocks","tag":"ss","server":"2.2.2.2","server_port":8388}]`
	cands, err := Parse([]byte(arr))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(cands) != 1 || cands[0].Security != "none" {
		t.Fatalf("unexpected candidates: %+v", cands)
	}
}

func TestParse_Empty(t *testing.T) {
	if _, err := Parse([]byte("  ")); err == nil {
		t.Error("expected error for empty input")
	}
}
