package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// tlsExtension is one parsed ClientHello extension (type + raw data).
type tlsExtension struct {
	Type uint16
	Data []byte
}

// parseExtensions extracts the ordered extensions (type + data) from a raw ClientHello
// handshake message. Returns nil on malformed input. parseExtensionTypes delegates here.
func parseExtensions(raw []byte) []tlsExtension {
	b := raw
	if len(b) >= 4 && b[0] == 0x01 {
		b = b[4:] // skip handshake header
	}
	i := 0
	if len(b) < 34 {
		return nil
	}
	i += 34 // legacy_version(2) + random(32)
	if i >= len(b) {
		return nil
	}
	i += 1 + int(b[i]) // session_id
	if i+2 > len(b) {
		return nil
	}
	csLen := int(b[i])<<8 | int(b[i+1])
	i += 2 + csLen // cipher_suites
	if i+1 > len(b) {
		return nil
	}
	i += 1 + int(b[i]) // compression_methods
	if i+2 > len(b) {
		return nil
	}
	extTotal := int(b[i])<<8 | int(b[i+1])
	i += 2
	end := i + extTotal
	if end > len(b) {
		end = len(b)
	}
	var exts []tlsExtension
	for i+4 <= end {
		et := uint16(b[i])<<8 | uint16(b[i+1])
		el := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if i+el > end {
			break
		}
		exts = append(exts, tlsExtension{Type: et, Data: b[i : i+el]})
		i += el
	}
	return exts
}

// computeJA4 returns the JA4 TLS client fingerprint of the ClientHello uTLS built,
// following the FoxIO JA4 spec: ja4_a_ja4_b_ja4_c. Used for shareable telemetry (Vector B).
//
// NOTE: spec-faithful but not yet cross-validated against FoxIO reference vectors.
func computeJA4(hello *utls.PubClientHelloMsg) string {
	if hello == nil {
		return ""
	}
	exts := parseExtensions(hello.Raw)

	// --- JA4_a ---
	proto := "t" // TLS over TCP (our probes are always TCP)
	ver := ja4Version(hello, exts)
	sni := "i"
	if hasExtension(exts, 0x0000) { // server_name
		sni = "d"
	}
	ciphers := filterGREASE(hello.CipherSuites)
	extTypes := filterGREASE(extensionTypes(exts))
	alpn := ja4ALPN(exts)
	ja4a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, ver, sni, capped(len(ciphers)), capped(len(extTypes)), alpn)

	// --- JA4_b: sha256(sorted ciphers) truncated to 12 hex ---
	ja4b := truncSHA256(hexJoinSorted(ciphers))

	// --- JA4_c: sha256(sorted extensions minus SNI/ALPN, "_", sig algs in order) ---
	var forHash []uint16
	for _, e := range extTypes {
		if e == 0x0000 || e == 0x0010 { // exclude SNI and ALPN
			continue
		}
		forHash = append(forHash, e)
	}
	sigAlgs := ja4SigAlgs(exts) // in original order
	ja4c := truncSHA256(hexJoinSorted(forHash) + "_" + hexJoin(sigAlgs))

	return ja4a + "_" + ja4b + "_" + ja4c
}

func extensionTypes(exts []tlsExtension) []uint16 {
	out := make([]uint16, len(exts))
	for i, e := range exts {
		out[i] = e.Type
	}
	return out
}

func hasExtension(exts []tlsExtension, t uint16) bool {
	for _, e := range exts {
		if e.Type == t {
			return true
		}
	}
	return false
}

// ja4Version maps the highest offered TLS version to JA4's 2-char code, reading the
// supported_versions extension (0x002b) if present, else the legacy version.
func ja4Version(hello *utls.PubClientHelloMsg, exts []tlsExtension) string {
	best := uint16(hello.Vers)
	for _, e := range exts {
		if e.Type != 0x002b || len(e.Data) < 1 {
			continue
		}
		list := e.Data[1:] // first byte is list length
		for i := 0; i+2 <= len(list); i += 2 {
			v := uint16(list[i])<<8 | uint16(list[i+1])
			if isGREASE(v) {
				continue
			}
			if v > best {
				best = v
			}
		}
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

// ja4ALPN returns the first ALPN value's first+last char, or "00" if absent.
func ja4ALPN(exts []tlsExtension) string {
	for _, e := range exts {
		if e.Type != 0x0010 || len(e.Data) < 3 {
			continue
		}
		// data: 2-byte list length, then 1-byte proto length + proto bytes
		p := e.Data[2:]
		if len(p) < 1 {
			return "00"
		}
		n := int(p[0])
		if n == 0 || 1+n > len(p) {
			return "00"
		}
		proto := p[1 : 1+n]
		return string([]byte{proto[0], proto[len(proto)-1]})
	}
	return "00"
}

// ja4SigAlgs returns the signature_algorithms (0x000d) values in original order.
func ja4SigAlgs(exts []tlsExtension) []uint16 {
	for _, e := range exts {
		if e.Type != 0x000d || len(e.Data) < 2 {
			continue
		}
		list := e.Data[2:] // 2-byte list length
		var out []uint16
		for i := 0; i+2 <= len(list); i += 2 {
			out = append(out, uint16(list[i])<<8|uint16(list[i+1]))
		}
		return out
	}
	return nil
}

func capped(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func truncSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func hexJoin(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hexJoinSorted(vals []uint16) string {
	cp := append([]uint16(nil), vals...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return hexJoin(cp)
}
