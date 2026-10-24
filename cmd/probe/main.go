package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k0ssk0ss-ai/netprobe/pkg/adapter"
	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

func main() {
	// EN: Add command-line flags for different modes of operation
	// RU: Добавляем флаги командной строки для разных режимов использования
	daemonMode := flag.Bool("daemon", false, "Start as background web server with UI (Запустить как фоновый веб-сервер с UI)")
	targetHost := flag.String("target", "", "Target domain for testing (Домен для проверки)")
	configPath := flag.String("config", "", "sing-box config file — enables the decision engine (Vector A)")
	outPath := flag.String("out", "", "write the clean JSON report to this file instead of stdout")
	flag.Parse()

	if *daemonMode {
		runDaemon()
	} else if *targetHost != "" {
		runCLI(*targetHost, *configPath, *outPath)
	} else {
		runMassScan()
	}
}

func runCLI(target, configPath, outPath string) {
	fmt.Fprintf(os.Stderr, "Starting NetProbe analysis for target: %s\n", target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report := engine.RunEngineScans(ctx, target)

	// EN: If a sing-box config is supplied, run Vector A and attach the decision.
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			log.Fatalf("read config %q: %v", configPath, err)
		}
		cands, err := adapter.Parse(data)
		if err != nil {
			log.Fatalf("parse config: %v", err)
		}
		// EN: Accurate mode — actively probe each candidate's own endpoint.
		actx, acancel := context.WithTimeout(context.Background(), 8*time.Second)
		report.Decision = engine.DecideOutboundActive(actx, report, cands)
		acancel()
	}

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("JSON marshal error: %v", err)
	}

	// EN: With -out, write clean JSON to a file (the status line went to stderr, so the
	// EN: file stays valid). Otherwise print to stdout.
	if outPath != "" {
		if err := os.WriteFile(outPath, b, 0644); err != nil {
			log.Fatalf("write report %q: %v", outPath, err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", outPath)
		return
	}
	fmt.Println(string(b))
}

// EN: runMassScan runs a battery of tests for everyday users who just double click the .exe
// RU: runMassScan запускает пачку тестов для простых юзеров, которые просто кликают по .exe
func runMassScan() {
	fmt.Println("===================================================")
	fmt.Println(" NetProbe v" + version + " - Анализатор блокировок (NTC Edition)")
	fmt.Println("===================================================")
	fmt.Println("Анализируем вашу сеть на наличие ТСПУ и DPI...")
	fmt.Println()

	domains := []string{
		"youtube.com",
		"web.telegram.org",
		"discord.com",
		"instagram.com",
		"twitter.com",
	}

	var allReports []engine.ProbeReport
	var summary []string

	for i, domain := range domains {
		fmt.Printf("[%d/%d] Проверка %s... ", i+1, len(domains), domain)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		report := engine.RunEngineScans(ctx, domain)
		cancel()

		allReports = append(allReports, report)

		blockReason := "Чисто"
		if report.Results.DPI.SNIBlocked || report.Results.DPI.HTTPBlocked {
			blockReason = report.Results.DPI.BlockMethod
		} else if report.Results.DNS.SpoofingDetected {
			blockReason = "DNS Spoofing"
		} else if len(report.Results.DNS.ResolvedIPs) == 0 {
			blockReason = "DNS Error / Blackhole"
		} else if len(report.Results.DPI.Errors) > 0 && !strings.Contains(report.Results.DPI.Errors[0], "[Clean]") {
			blockReason = "Ошибка сети"
		}

		fmt.Printf("%s\n", blockReason)
		summary = append(summary, domain+": "+blockReason)
	}

	fmt.Println("\n[!] Подводим итоги по транспорту:")
	if len(allReports) > 0 {
		if allReports[0].Results.Transport.UDP443Works {
			fmt.Println(" [+] QUIC (UDP 443) статус: ОТКРЫТ (Идеально для Hysteria2/TUIC)")
			summary = append(summary, "UDP 443: открыт")
		} else {
			fmt.Println(" [-] QUIC (UDP 443) статус: ЗАБЛОКИРОВАН (Используйте TCP/VLESS или нестандартные порты)")
			summary = append(summary, "UDP 443: закрыт")
		}
	}

	savedPath := ""
	b, err := json.MarshalIndent(allReports, "", "  ")
	if err == nil {
		cwd, errCwd := os.Getwd()
		if errCwd == nil {
			filePath := filepath.Join(cwd, "netprobe_report.json")
			errFile := os.WriteFile(filePath, b, 0644)
			if errFile == nil {
				savedPath = filePath
				fmt.Println("\n===================================================")
				fmt.Printf("Детальный отчет успешно сохранен в файл:\n👉 %s\n", filePath)
				fmt.Println("Пожалуйста, выделите этот путь, скопируйте его и вставьте в Проводник.")
				fmt.Println("Файл 'netprobe_report.json' можно прикрепить к сообщению на форуме.")
			}
		}
	}

	in := bufio.NewReader(os.Stdin)
	offerUpload(in, summary, allReports, savedPath)

	fmt.Println("\nНажмите Enter для выхода...")
	readLine(in)
}

// EN: runDaemon starts the hybrid system (Backend API + Web UI)
// RU: runDaemon — запуск гибридной системы (бэкенд + веб-интерфейс)
func runDaemon() {
	fmt.Println("===================================================")
	fmt.Println(" NetProbe (Daemon & Web UI)")
	fmt.Println("===================================================")

	http.Handle("/", http.FileServer(http.Dir("./web")))

	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, fmt.Sprintf(`{"error": "Internal server error: %v"}`, err), http.StatusInternalServerError)
			}
		}()

		target := r.URL.Query().Get("target")
		if target == "" {
			target = "twitter.com"
		}

		fmt.Printf("[*] Scan request received for: %s\n", target)

		// EN: Launch the concurrent scanner
		// RU: Запускаем параллельный сканер
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		report := engine.RunEngineScans(ctx, target)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)

		fmt.Println("[+] Report successfully sent to browser.")
	})

	port := ":8080"
	fmt.Printf("[*] Background daemon started!\n")
	fmt.Printf("[*] Open in browser: http://127.0.0.1%s\n", port)
	fmt.Printf("[*] For pure CLI JSON output use: ./probe -target=example.com\n")

	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("Server start error: ", err)
	}
}
