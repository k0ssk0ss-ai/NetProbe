package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/antigravity/netprobe/pkg/engine"
)

func main() {
	// EN: Add command-line flags for different modes of operation
	// RU: Добавляем флаги командной строки для разных режимов использования
	daemonMode := flag.Bool("daemon", false, "Start as background web server with UI (Запустить как фоновый веб-сервер с UI)")
	targetHost := flag.String("target", "twitter.com", "Target domain for testing (Домен для проверки)")
	flag.Parse()

	if *daemonMode {
		runDaemon()
	} else {
		runCLI(*targetHost)
	}
}

// EN: runEngineScans executes all network checks concurrently using goroutines
// RU: runEngineScans выполняет все сетевые проверки параллельно (горутины)
func runEngineScans(target string) engine.ProbeReport {
	report := engine.ProbeReport{
		Timestamp:  time.Now(),
		TargetHost: target,
	}

	var transportRes engine.TransportResult
	var dpiRes engine.DPIResult
	var dnsRes engine.DNSResult

	var wg sync.WaitGroup
	wg.Add(3)

	// EN: Resolve a trusted clean IP first to avoid false positives
	// RU: Получаем чистый IP перед стартом
	cleanIP := engine.GetCleanIP()

	// EN: Run 3 independent scanners in parallel
	// RU: Запускаем 3 независимых сканера параллельно
	go func() {
		defer wg.Done()
		transportRes = engine.CheckTransport(cleanIP)
	}()

	go func() {
		defer wg.Done()
		dpiRes = engine.CheckDPI(cleanIP, target)
	}()

	go func() {
		defer wg.Done()
		dnsRes = engine.CheckDNS(target)
	}()

	// EN: Wait for the longest test to complete (max 3 seconds)
	// RU: Ждем завершения самого долгого теста (максимум 3 сек)
	wg.Wait()

	report.Results.Transport = transportRes
	report.Results.DPI = dpiRes
	report.Results.DNS = dnsRes

	// EN: Strategy engine appends recommendations to the report
	// RU: Движок принятия решений добавляет рекомендации в отчет
	engine.AnalyzeResults(&report)

	return report
}

// EN: runCLI is the mode for scripts and parsers. It outputs pure JSON to stdout.
// RU: runCLI — режим для парсеров и программистов. Выводит чистый JSON.
func runCLI(target string) {
	report := runEngineScans(target)

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonBytes))
}

// EN: runDaemon starts the hybrid system (Backend API + Web UI)
// RU: runDaemon — запуск гибридной системы (бэкенд + веб-интерфейс)
func runDaemon() {
	fmt.Println("===================================================")
	fmt.Println(" NetProbe (Daemon & Web UI)")
	fmt.Println("===================================================")

	http.Handle("/", http.FileServer(http.Dir("./web")))

	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			target = "twitter.com"
		}

		fmt.Printf("[*] Scan request received for: %s\n", target)

		// EN: Launch the concurrent scanner
		// RU: Запускаем параллельный сканер
		report := runEngineScans(target)

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
