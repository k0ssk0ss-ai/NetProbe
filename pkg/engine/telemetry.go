package engine

// Vector B seed — SCAFFOLD ONLY. Telemetry in a privacy tool is a landmine (see
// ROADMAP.md §8): default is OFF, there is no network here, and nothing leaves the
// device unless an integrator explicitly opts in by setting Sink. When a real network
// is built it must be demonstratively paranoid: opt-in, no identifiers, aggregate to
// ASN/region, open protocol.

// TelemetrySink receives anonymized interference reports IF telemetry is enabled.
type TelemetrySink interface {
	Report(AnonReport)
}

// Sink is the optional telemetry destination. nil = telemetry disabled (the default).
// An integrator must set it explicitly for any data to leave the device.
var Sink TelemetrySink

// AnonReport is the anonymized, shareable subset: the censorship signal only. It
// deliberately omits resolved IPs, error strings (which may carry local addresses), and
// anything identifying.
type AnonReport struct {
	SchemaVersion int               `json:"schema_version"`
	Target        string            `json:"target"`
	Vantage       *Vantage          `json:"vantage,omitempty"` // coarse (ASN/region), only if the integrator set it
	SNIBlocked    bool              `json:"sni_blocked"`
	TLSBlocked    bool              `json:"tls_blocked"`
	BlockMethod   string            `json:"block_method,omitempty"`
	UDP443Works   bool              `json:"udp_443_works"`
	Fingerprints  []AnonFingerprint `json:"fingerprints,omitempty"`
}

// AnonFingerprint is the shareable per-profile result: which ClientHello shape (by JA3/JA4)
// survived — no destination detail.
type AnonFingerprint struct {
	JA3     string `json:"ja3,omitempty"`
	JA4     string `json:"ja4,omitempty"`
	Verdict string `json:"verdict"`
}

// Anonymize strips a ProbeReport down to shareable signal. It never copies IPs or errors.
func Anonymize(r ProbeReport) AnonReport {
	a := AnonReport{
		SchemaVersion: r.SchemaVersion,
		Target:        r.TargetHost,
		Vantage:       r.Vantage,
		SNIBlocked:    r.Results.DPI.SNIBlocked,
		TLSBlocked:    r.Results.DNS.TLSBlocked,
		BlockMethod:   r.Results.DPI.BlockMethod,
		UDP443Works:   r.Results.Transport.UDP443Works,
	}
	for _, f := range r.FingerprintMatrix {
		a.Fingerprints = append(a.Fingerprints, AnonFingerprint{JA3: f.JA3, JA4: f.JA4, Verdict: f.Verdict})
	}
	return a
}

// emitTelemetry hands the report to Sink if and only if one is configured. No-op by default.
func emitTelemetry(r ProbeReport) {
	if Sink != nil {
		Sink.Report(Anonymize(r))
	}
}
