package main

// EN: Support upload: after the double-click scan the user presses Enter and the
// EN: report goes to a support bot. Off unless reportURL is baked in at build time:
// EN:   go build -ldflags "-X main.reportURL=https://example.com/api/my/netreport" ./cmd/probe
// EN: A support code is read from the exe's own file name (netprobe_<CODE>.exe), which
// EN: is how the bot ships it; without one the user may type a name instead.
// RU: Отправка в поддержку. Выключена, пока reportURL не задан при сборке.
// RU: Код поддержки берётся из имени файла netprobe_<КОД>.exe.

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
	version   = "2.5" // shown to support next to the report
)

var codeRe = regexp.MustCompile(`(?i)netprobe[_-]([A-Z0-9]{6})`)

// supportPayload is what the support endpoint receives. The probe reports carry no
// client IP — only the per-domain verdicts and resolved target addresses.
type supportPayload struct {
	Code    string               `json:"code,omitempty"`
	Name    string               `json:"name,omitempty"`
	Version string               `json:"version"`
	OS      string               `json:"os"`
	Summary []string             `json:"summary"`
	Reports []engine.ProbeReport `json:"reports"`
}

func codeFromExe(path string) string {
	m := codeRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1])
}

// offerUpload asks once and sends. Any failure ends with a hint to send the file by hand.
func offerUpload(in *bufio.Reader, summary []string, reports []engine.ProbeReport, savedPath string) {
	if reportURL == "" {
		return
	}
	exe, _ := os.Executable()
	code := codeFromExe(exe)
	if code == "" {
		code = codeFromExe(os.Args[0])
	}

	fmt.Println("\n===================================================")
	fmt.Print("Отправить отчёт в поддержку? Enter — да, n — нет: ")
	if ans := readLine(in); strings.HasPrefix(strings.ToLower(ans), "n") || strings.HasPrefix(ans, "н") {
		fmt.Println("Не отправляем.")
		return
	}
	p := supportPayload{Code: code, Version: version, OS: runtime.GOOS + "/" + runtime.GOARCH,
		Summary: summary, Reports: reports}
	if code == "" {
		fmt.Print("Ваш ник в Telegram или имя (чтобы мы поняли, чей отчёт): ")
		p.Name = readLine(in)
	}

	fmt.Println("Отправляем...")
	if err := upload(p); err != nil {
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

// upload tries the system resolver first, then the same host via a DoH-resolved IP —
// a hijacked or blocked DNS answer for the support domain must not stop delivery.
func upload(p supportPayload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	first := post(http.DefaultClient, body)
	if first == nil {
		return nil
	}
	u, err := url.Parse(reportURL)
	if err != nil {
		return first
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := engine.GetTrustedDoH(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return first
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
	if err := post(c, body); err != nil {
		return first
	}
	return nil
}

func post(c *http.Client, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reportURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("сервер ответил %d", resp.StatusCode)
	}
	return nil
}
