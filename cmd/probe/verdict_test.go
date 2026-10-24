package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func b(v bool) *bool { return &v }

func hosting(cf, ovh, hz int64) []Fetch {
	return []Fetch{{Name: "Cloudflare", Bytes: cf}, {Name: "OVH", Bytes: ovh}, {Name: "Hetzner", Bytes: hz}, {Name: "Vultr", Bytes: hz}}
}

// One dead host among working ones is not "the ISP cuts hosting".
func TestOneHostOutlier(t *testing.T) {
	r := Reach{Hosting: []Fetch{{Name: "Cloudflare", Bytes: 1e6}, {Name: "OVH", Bytes: 1e6}, {Name: "Hetzner"}, {Name: "Vultr", Bytes: 1e6}}}
	if got := joined(r, nil); strings.Contains(got, "хостинг") {
		t.Errorf("outlier reported:\n%s", got)
	}
}

// Salamander round trip: what one side masks the other unmasks.
func TestSalamanderRoundTrip(t *testing.T) {
	ca, _ := net.ListenPacket("udp", "127.0.0.1:0")
	cb, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer ca.Close()
	defer cb.Close()
	sa, sb := newSalamander(ca, "pw"), newSalamander(cb, "pw")
	msg := []byte("hello quic initial packet")
	if _, err := sa.WriteTo(msg, cb.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	_ = cb.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := sb.ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(msg) {
		t.Fatalf("got %q err %v", buf[:n], err)
	}
}

func joined(r Reach, s []SiteVerdict) string { return strings.Join(Verdict(r, s), "\n") }

// Kolya 24.10: foreign hosting gets 0 bytes, our TCP dead, Hy2 dead, AWG (plain UDP) works.
func TestKolyaCase(t *testing.T) {
	r := Reach{Hosting: hosting(1e6, 0, 0), Server: &Fetch{Name: "server"}, Hy2: b(false), UDP: b(true)}
	got := joined(r, []SiteVerdict{{"youtube.com", "RST"}, {"discord.com", "Чисто"}})
	for _, want := range []string{"не пропускает данные к зарубежным хостингам", "TCP — данные не приходят", "Amnezia", "YouTube"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Discord") {
		t.Errorf("clean site listed as blocked:\n%s", got)
	}
}

func TestAdviceOrder(t *testing.T) {
	cases := []struct {
		tcp, hy2, udp bool
		want          string
	}{
		{true, true, true, "обычное подключение в Happ. Если"},
		{true, false, true, "Hysteria2 у вашего провайдера не работает"},
		{false, true, false, "выберите сервер с Hysteria2"},
		{false, false, true, "Amnezia"},
		{false, false, false, "российский сервер"},
	}
	for _, c := range cases {
		if got := advice(c.tcp, c.hy2, c.udp, true, true); !strings.Contains(got, c.want) {
			t.Errorf("advice(%v,%v,%v) = %q, want %q", c.tcp, c.hy2, c.udp, got, c.want)
		}
	}
}

func TestThrottleAndVPNWarning(t *testing.T) {
	r := Reach{Hosting: hosting(1e6, 16000, 16384), Server: &Fetch{Bytes: 16000}, VPN: []string{"AmneziaVPN"}}
	got := joined(r, nil)
	for _, want := range []string{"Включён VPN (AmneziaVPN)", "после ~16 КБ", "обрывается после 16 КБ"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestNoServerChecksWithoutConfig(t *testing.T) {
	got := joined(Reach{Hosting: hosting(1e6, 1e6, 1e6)}, []SiteVerdict{{"discord.com", "Чисто"}})
	if strings.Contains(got, "Наш сервер") || strings.Contains(got, "хостинг") {
		t.Errorf("unexpected lines:\n%s", got)
	}
}

// A handshake timeout must not count as "UDP answered" (the old UDP443 check did).
func TestQuicTimeoutIsNotAnswer(t *testing.T) {
	if quicAnswered(&quic.HandshakeTimeoutError{}) || quicAnswered(&quic.IdleTimeoutError{}) || quicAnswered(context.DeadlineExceeded) {
		t.Error("timeout treated as answer")
	}
	if !quicAnswered(&quic.TransportError{ErrorCode: 0x100 + 40}) {
		t.Error("TLS alert from server not treated as answer")
	}
	if quicAnswered(errors.New("random")) {
		t.Error("unknown error treated as answer")
	}
}

func TestCodeFromExe(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\x\Downloads\netprobe_K7Q2C9.exe`:     "K7Q2C9",
		`C:\Users\x\Downloads\netprobe_K7Q2C9 (1).exe`: "K7Q2C9",
		`probe.exe`: "",
	} {
		if got := codeFromExe(in); got != want {
			t.Errorf("codeFromExe(%q) = %q, want %q", in, got, want)
		}
	}
}
