package engine

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// computeJA3 returns the JA3 fingerprint (MD5 hex) of the ClientHello uTLS built.
// JA3 = md5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats), where each
// group is a "-"-joined list of decimal values with GREASE removed. Used for shareable
// telemetry (Vector B): the JA3 identifies exactly which ClientHello shape was RST'd.
func computeJA3(hello *utls.PubClientHelloMsg) string {
	if hello == nil {
		return ""
	}

	ver := strconv.Itoa(int(hello.Vers))
	ciphers := joinUint16(filterGREASE(hello.CipherSuites))
	exts := joinUint16(filterGREASE(parseExtensionTypes(hello.Raw)))
	curves := joinUint16(filterGREASE(curveIDs(hello.SupportedCurves)))
	points := joinUint8(hello.SupportedPoints)

	ja3 := strings.Join([]string{ver, ciphers, exts, curves, points}, ",")
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// parseExtensionTypes extracts the ordered extension type IDs from a raw ClientHello.
// Returns nil if the buffer is malformed (JA3 is then omitted).
func parseExtensionTypes(raw []byte) []uint16 {
	return extensionTypes(parseExtensions(raw))
}

// isGREASE reports whether v is a GREASE value (RFC 8701): high byte == low byte and
// both low nibbles are 0xa (0x0a0a, 0x1a1a, … 0xfafa).
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v&0xff)
	return hi == lo && (lo&0x0f) == 0x0a
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func curveIDs(in []utls.CurveID) []uint16 {
	out := make([]uint16, len(in))
	for i, c := range in {
		out[i] = uint16(c)
	}
	return out
}

func joinUint16(in []uint16) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinUint8(in []uint8) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}
