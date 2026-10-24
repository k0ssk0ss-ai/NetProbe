package main

// EN: Reachability of foreign hosting and of the operator's own VPN server: how many
// EN: bytes actually arrive (TSPU lets the TCP handshake through and then freezes the
// EN: flow at ~16 KB or sends nothing), whether QUIC to the Hysteria2 port completes,
// EN: and whether plain UDP passes (a magic-prefixed echo on the server) — the path
// EN: AmneziaWG relies on. Our-server checks are off unless serverHost is baked in:
// EN:   -X main.serverHost=node.example.com -X main.serverIP=1.2.3.4
// EN:   -X main.hy2Port=48445 -X main.echoPort=45700 -X main.hy2Obfs=<salamander password>
// RU: Проверка зарубежных хостингов и нашего сервера: сколько байт реально приходит,
// RU: проходит ли QUIC до Hysteria2 и простой UDP (эхо) — путь AmneziaWG.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
	"github.com/quic-go/quic-go"
)

var (
	serverHost = "" // TLS name of the VPN server (also serves /files/1mb.bin)
	serverIP   = "" // fallback when DoH cannot resolve serverHost
	hy2Port    = "" // Hysteria2 UDP port
	echoPort   = "" // UDP echo port (deploy/myvpn/udpecho.py)
)

const (
	fullBytes  = 1_000_000
	echoMagic  = "SOCOKPROBE"
	fetchLimit = 15 * time.Second
)

// Fetch is one download attempt: how many bytes arrived before the limit.
type Fetch struct {
	Name  string  `json:"name"`
	Bytes int64   `json:"bytes"`
	Secs  float64 `json:"secs"`
	Err   string  `json:"err,omitempty"`
}

// State reads the byte count the way TSPU behaviour shows up.
func (f Fetch) State() string {
	switch {
	case f.Bytes >= fullBytes:
		return "ok"
	case f.Bytes > 5000 && f.Bytes < 40000:
		return "16kb"
	case f.Bytes == 0:
		return "none"
	}
	return "partial"
}

// Reach is everything the verdict needs beyond the per-site scan.
type Reach struct {
	Hosting  []Fetch  `json:"hosting"`             // CF, OVH, Hetzner, Vultr
	Server   *Fetch   `json:"server,omitempty"`    // our server over TCP 443
	ServerIP string   `json:"server_ip,omitempty"` // address actually dialled
	Hy2      *bool    `json:"hy2,omitempty"`       // QUIC handshake to Hysteria2 completed
	UDP      *bool    `json:"udp,omitempty"`       // plain UDP echo came back
	UDPms    float64  `json:"udp_ms,omitempty"`
	VPN      []string `json:"vpn_adapters,omitempty"` // tunnel adapters that are up
}

var hostingURLs = []struct{ name, url string }{
	{"Cloudflare", "https://speed.cloudflare.com/__down?bytes=1000000"},
	{"OVH", "https://proof.ovh.net/files/1Mb.dat"},
	{"Hetzner", "https://nbg1-speed.hetzner.com/100MB.bin"},
	{"Vultr", "https://fra-de-ping.vultr.com/vultr.com.100MB.bin"},
}

func runReach() Reach {
	var r Reach
	r.VPN = vpnAdapters()
	var wg sync.WaitGroup
	var mu sync.Mutex
	r.Hosting = make([]Fetch, len(hostingURLs))
	for i, h := range hostingURLs {
		wg.Add(1)
		go func(i int, name, url string) {
			defer wg.Done()
			f := fetch(name, url, "")
			mu.Lock()
			r.Hosting[i] = f
			mu.Unlock()
		}(i, h.name, h.url)
	}
	if serverHost != "" {
		r.ServerIP = resolveServer()
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := fetch("server", "https://"+serverHost+"/files/1mb.bin", r.ServerIP)
			mu.Lock()
			r.Server = &f
			mu.Unlock()
		}()
		if hy2Port != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok := quicOK(net.JoinHostPort(r.ServerIP, hy2Port), serverHost)
				mu.Lock()
				r.Hy2 = &ok
				mu.Unlock()
			}()
		}
		if echoPort != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, ms := udpEcho(net.JoinHostPort(r.ServerIP, echoPort))
				mu.Lock()
				r.UDP, r.UDPms = &ok, ms
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	return r
}

func resolveServer() string {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if ips, err := engine.GetTrustedDoH(ctx, serverHost); err == nil && len(ips) > 0 {
		return ips[0]
	}
	return serverIP
}

// fetch downloads up to 1 MB; pin dials that IP directly (bypassing DNS) with the
// URL's host as SNI — the same TCP 443 path a Reality client takes.
func fetch(name, url, pin string) Fetch {
	tr := &http.Transport{TLSHandshakeTimeout: 8 * time.Second, DisableCompression: true}
	if pin != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, network, net.JoinHostPort(pin, port))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchLimit)
	defer cancel()
	start := time.Now()
	f := Fetch{Name: name}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f.Err = err.Error()
		return f
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", fullBytes-1))
	// Hetzner drops both "Go-http-client" and a bare browser UA (EOF), but serves an
	// honest tool name — measured 24.10.
	req.Header.Set("User-Agent", "NetProbe/"+version)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		f.Err = shortErr(err)
	} else {
		f.Bytes, err = io.Copy(io.Discard, io.LimitReader(resp.Body, fullBytes))
		resp.Body.Close()
		if err != nil && f.Bytes < fullBytes {
			f.Err = shortErr(err)
		}
	}
	f.Secs = float64(time.Since(start).Milliseconds()) / 1000
	return f
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		s = s[i+2:]
	}
	return s
}

// quicOK is true only when the handshake finishes or the server answers with a TLS
// alert — both prove UDP round trips. A timeout means the packets died on the way.
func quicOK(addr, sni string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return false
	}
	defer udp.Close()
	var pc net.PacketConn = udp
	if hy2Obfs != "" {
		pc = newSalamander(udp, hy2Obfs)
	}
	tr := &quic.Transport{Conn: pc}
	defer tr.Close()
	conn, err := tr.Dial(ctx, raddr,
		&tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&quic.Config{HandshakeIdleTimeout: 4 * time.Second})
	if err == nil {
		conn.CloseWithError(0, "probe")
		return true
	}
	return quicAnswered(err)
}

// quicAnswered: did the server reply at all? Timeouts and context ends mean no.
func quicAnswered(err error) bool {
	var hto *quic.HandshakeTimeoutError
	var ito *quic.IdleTimeoutError
	if errors.As(err, &hto) || errors.As(err, &ito) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var te *quic.TransportError
	return errors.As(err, &te) // CRYPTO_ERROR etc. came from the server
}

// udpEcho sends three magic-prefixed packets; any echo back means plain UDP passes.
func udpEcho(addr string) (bool, float64) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false, 0
	}
	defer conn.Close()
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	msg := append([]byte(echoMagic), nonce...)
	buf := make([]byte, 64)
	for i := 0; i < 3; i++ {
		start := time.Now()
		_, _ = conn.Write(msg)
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err == nil && n == len(msg) && string(buf[:n]) == string(msg) {
			return true, float64(time.Since(start).Microseconds()) / 1000
		}
	}
	return false, 0
}

// vpnAdapters lists up interfaces that look like a tunnel: with one up, results
// describe the tunnel, not the ISP.
func vpnAdapters() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	marks := []string{"wintun", "amnezia", "wireguard", "tun", "tap", "happ", "v2ray", "sing", "clash", "nekoray", "outline", "openvpn", "wg"}
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		low := strings.ToLower(i.Name)
		for _, m := range marks {
			if strings.Contains(low, m) {
				out = append(out, i.Name)
				break
			}
		}
	}
	return out
}

func derefFetch(f *Fetch) []Fetch {
	if f == nil {
		return nil
	}
	return []Fetch{*f}
}
