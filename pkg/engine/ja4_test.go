package engine

import (
	"net"
	"regexp"
	"testing"

	utls "github.com/refraction-networking/utls"
)

var ja4Re = regexp.MustCompile(`^t\d\d[di]\d\d\d\d.._[0-9a-f]{12}_[0-9a-f]{12}$`)

func buildJA4(t *testing.T, id utls.ClientHelloID) string {
	t.Helper()
	c, _ := net.Pipe()
	defer c.Close()
	u := utls.UClient(c, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, id)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	return computeJA4(u.HandshakeState.Hello)
}

func TestComputeJA4_Format(t *testing.T) {
	ja4 := buildJA4(t, utls.HelloFirefox_Auto)
	if !ja4Re.MatchString(ja4) {
		t.Errorf("JA4 %q does not match expected shape t<ver><sni><nc><ne><alpn>_<12hex>_<12hex>", ja4)
	}
	// TLS 1.3 ClientHello with SNI set → starts "t13d".
	if ja4[:4] != "t13d" {
		t.Errorf("JA4 prefix = %q, want t13d", ja4[:4])
	}
}

// TestComputeJA4_Deterministic: JA4 is shuffle-resistant (sorts ciphers/extensions), so
// even Chrome — which shuffles extension order — yields a stable JA4 (unlike JA3).
func TestComputeJA4_Deterministic(t *testing.T) {
	for _, id := range []struct {
		name string
		hello utls.ClientHelloID
	}{
		{"firefox", utls.HelloFirefox_Auto},
		{"chrome", utls.HelloChrome_Auto},
	} {
		a := buildJA4(t, id.hello)
		b := buildJA4(t, id.hello)
		if a != b {
			t.Errorf("%s JA4 not deterministic: %q != %q", id.name, a, b)
		}
	}
}

func TestComputeJA4_DistinctBrowsers(t *testing.T) {
	if buildJA4(t, utls.HelloChrome_Auto) == buildJA4(t, utls.HelloFirefox_Auto) {
		t.Error("chrome and firefox JA4 should differ")
	}
}
