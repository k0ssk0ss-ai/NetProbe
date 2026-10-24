package main

// EN: Support upload: after the double-click scan the user presses Enter and the
// EN: report goes to a support bot. Off unless reportURL is baked in at build time:
// EN:   go build -ldflags "-X main.reportURL=https://example.com/api/my/netreport" ./cmd/probe
// EN: The support code comes from the exe's own file name (netprobe_<CODE>.exe, how a
// EN: bot ships it) or is typed at start (a public release); without one the user may
// EN: type a name instead. With a code the probe also fetches settings that are not
// EN: baked into a public binary (the Hysteria2 obfs password) from <base>/netcfg.
// RU: Отправка в поддержку. Код — из имени файла или вводом при запуске; по коду
// RU: программа берёт с сервера то, что в публичный exe не вшито (ключ Hy2).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

var (
	reportURL = ""    // set via -ldflags; empty disables the upload
	version   = "2.6" // shown to support next to the report
)

var codeRe = regexp.MustCompile(`(?i)netprobe[_-]([A-Z0-9]{6})`)
var typedRe = regexp.MustCompile(`^[A-Za-z0-9]{6}$`)

// supportPayload is what the support endpoint receives. The probe reports carry no
// client IP — only the per-domain verdicts and resolved target addresses.
type supportPayload struct {
	Code    string               `json:"code,omitempty"`
	Name    string               `json:"name,omitempty"`
	Version string               `json:"version"`
	OS      string               `json:"os"`
	Summary []string             `json:"summary"`
	Reports []engine.ProbeReport `json:"reports"`
	Reach   Reach                `json:"reach"`
}

func codeFromExe(path string) string {
	m := codeRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1])
}

// supportCode: from the file name, else asked once before the scan.
func supportCode(in *bufio.Reader) string {
	if reportURL == "" {
		return ""
	}
	exe, _ := os.Executable()
	if c := codeFromExe(exe); c != "" {
		return c
	}
	if c := codeFromExe(os.Args[0]); c != "" {
		return c
	}
	for i := 0; i < 2; i++ {
		fmt.Print("Код из приложения «Мой VPN» (Enter — без кода): ")
		s := readLine(in)
		if s == "" {
			return ""
		}
		if typedRe.MatchString(s) {
			return strings.ToUpper(s)
		}
		fmt.Println("Код — 6 латинских букв и цифр, например K7Q2C9.")
	}
	return ""
}

// loadConfig fetches per-code settings; a failure only narrows the checks.
func loadConfig(code string) {
	if code == "" || hy2Obfs != "" {
		return
	}
	var cfg struct {
		Hy2Obfs string `json:"hy2_obfs"`
		Error   string `json:"error"`
	}
	b, err := send(siblingURL("netcfg"), map[string]string{"code": code})
	if err != nil {
		fmt.Printf("[-] Настройки по коду не получены (%v) — Hysteria2 проверим без них.\n", err)
		return
	}
	if json.Unmarshal(b, &cfg) == nil {
		hy2Obfs = cfg.Hy2Obfs
	}
}

func siblingURL(name string) string {
	i := strings.LastIndex(reportURL, "/")
	return reportURL[:i+1] + name
}

// offerUpload asks once and sends. Any failure ends with a hint to send the file by hand.
func offerUpload(in *bufio.Reader, code string, summary []string, reports []engine.ProbeReport, reach Reach, savedPath string) {
	if reportURL == "" {
		return
	}
	fmt.Println("\n===================================================")
	fmt.Print("Отправить отчёт в поддержку? Enter — да, n — нет: ")
	if ans := readLine(in); strings.HasPrefix(strings.ToLower(ans), "n") || strings.HasPrefix(ans, "н") {
		fmt.Println("Не отправляем.")
		return
	}
	p := supportPayload{Code: code, Version: version, OS: runtime.GOOS + "/" + runtime.GOARCH,
		Summary: summary, Reports: reports, Reach: reach}
	if code == "" {
		fmt.Print("Ваш ник в Telegram или имя (чтобы мы поняли, чей отчёт): ")
		p.Name = readLine(in)
	}

	fmt.Println("Отправляем...")
	if _, err := send(reportURL, p); err != nil {
		fmt.Printf("[-] Не получилось отправить: %v\n", err)
		if savedPath != "" {
			fmt.Printf("    Пришлите боту файл вручную: %s\n", savedPath)
		}
		return
	}
	if code != "" {
		fmt.Println("[+] Отчёт отправлен. Ответим в чате с ботом.")
	} else {
		fmt.Println("[+] Отчёт отправлен.")
	}
}

func readLine(in *bufio.Reader) string {
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

// send POSTs JSON, trying the system resolver first, then the same host via a
// DoH-resolved IP — a hijacked or blocked DNS answer must not stop delivery.
func send(target string, v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out, first := post(http.DefaultClient, target, body)
	if first == nil {
		return out, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, first
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := engine.GetTrustedDoH(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, first
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}}
	if out, err = post(c, target, body); err != nil {
		return nil, first
	}
	return out, nil
}

func post(c *http.Client, target string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("сервер ответил %d", resp.StatusCode)
	}
	return b, nil
}
