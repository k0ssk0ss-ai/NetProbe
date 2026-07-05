package engine

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestIsGREASE(t *testing.T) {
	greased := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa}
	for _, v := range greased {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	normal := []uint16{0x0000, 0xc02f, 0x1301, 0x000a}
	for _, v := range normal {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}

func TestParseExtensionTypes(t *testing.T) {
	raw := []byte{
		0x01, 0x00, 0x00, 0x00, // handshake header (type=ClientHello, len ignored)
		0x03, 0x03, // legacy_version
	}
	raw = append(raw, make([]byte, 32)...) // random
	raw = append(raw,
		0x00, // session_id length = 0
		0x00, 0x02, 0xc0, 0x2f, // cipher_suites: len 2, one suite
		0x01, 0x00, // compression_methods: len 1, method 0
		0x00, 0x08, // extensions total length = 8
		0x00, 0x00, 0x00, 0x00, // ext type 0 (SNI), len 0
		0x00, 0x0a, 0x00, 0x00, // ext type 10 (supported_groups), len 0
	)

	got := parseExtensionTypes(raw)
	want := []uint16{0, 10}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parseExtensionTypes = %v, want %v", got, want)
	}
}

// TestComputeJA3 builds real uTLS ClientHellos (no network) and checks the JA3 output
// is well-formed, deterministic for a non-shuffling profile, and distinct across browsers.
func TestComputeJA3(t *testing.T) {
	build := func(id utls.ClientHelloID) string {
		c, _ := net.Pipe()
		defer c.Close()
		u := utls.UClient(c, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, id)
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatalf("BuildHandshakeState: %v", err)
		}
		return computeJA3(u.HandshakeState.Hello)
	}

	firefox := build(utls.HelloFirefox_Auto)
	if len(firefox) != 32 {
		t.Errorf("firefox JA3 = %q, want 32 hex chars", firefox)
	}
	// Firefox does not shuffle extensions, so its JA3 is stable.
	if firefox != build(utls.HelloFirefox_Auto) {
		t.Error("firefox JA3 is not deterministic")
	}

	chrome := build(utls.HelloChrome_Auto)
	if len(chrome) != 32 {
		t.Errorf("chrome JA3 = %q, want 32 hex chars", chrome)
	}
	if chrome == firefox {
		t.Error("chrome and firefox JA3 should differ")
	}
}
