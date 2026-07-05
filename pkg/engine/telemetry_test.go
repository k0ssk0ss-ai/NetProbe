package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

type recorderSink struct{ got *AnonReport }

func (r *recorderSink) Report(a AnonReport) { r.got = &a }

func sampleTelemetryReport() ProbeReport {
	var r ProbeReport
	r.SchemaVersion = SchemaVersion
	r.TargetHost = "twitter.com"
	r.Results.DNS.ResolvedIPs = []string{"172.66.0.227"}
	r.Results.DNS.TLSBlocked = true
	r.Results.DNS.Errors = []string{"read tcp 192.168.0.133:1->172.66.0.227:443: forcibly closed"}
	r.Results.DPI.SNIBlocked = true
	r.Results.DPI.BlockMethod = "TCP RST"
	r.FingerprintMatrix = []FingerprintResult{
		{Profile: "chrome", JA3: "abc123", JA4: "t13d1234h2_aaa_bbb", Verdict: FPVerdictRST},
	}
	return r
}

func TestAnonymize_DropsIdentifiers(t *testing.T) {
	a := Anonymize(sampleTelemetryReport())
	b, _ := json.Marshal(a)
	s := string(b)
	for _, leak := range []string{"172.66.0.227", "192.168.0.133"} {
		if strings.Contains(s, leak) {
			t.Errorf("AnonReport leaked %q: %s", leak, s)
		}
	}
	if len(a.Fingerprints) != 1 || a.Fingerprints[0].Verdict != FPVerdictRST {
		t.Errorf("fingerprints not copied: %+v", a.Fingerprints)
	}
	if !a.SNIBlocked || a.BlockMethod != "TCP RST" || !a.TLSBlocked {
		t.Errorf("signal not preserved: %+v", a)
	}
}

func TestSink_OptInOnly(t *testing.T) {
	// Default: no sink → emitTelemetry must be a no-op (no panic).
	Sink = nil
	emitTelemetry(sampleTelemetryReport())

	rec := &recorderSink{}
	Sink = rec
	t.Cleanup(func() { Sink = nil })

	emitTelemetry(sampleTelemetryReport())
	if rec.got == nil {
		t.Fatal("sink did not receive report after opt-in")
	}
	if rec.got.Target != "twitter.com" {
		t.Errorf("target = %q, want twitter.com", rec.got.Target)
	}
}
