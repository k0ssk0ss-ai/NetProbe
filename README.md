# ⚡ NetProbe: Smart Proxy & DPI Detection Engine

[![Go Reference](https://pkg.go.dev/badge/github.com/k0ssk0ss-ai/netprobe.svg)](https://pkg.go.dev/github.com/k0ssk0ss-ai/netprobe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English](#english) | [Русский](#русский)

> [!WARNING]
> **Beta Software / Experimental**
> This project is an experimental Proof-of-Concept. It has not been subjected to extensive real-world testing across different ISPs and censorship environments. Expect bugs, false positives in heuristics, and potential instability.
> 
> **Экспериментальное ПО**
> Проект находится в стадии беты и является экспериментальным концептом. Код не проходил массового тестирования в боевых условиях разных провайдеров. Возможны баги, зависания, ложные срабатывания эвристики и нестабильная работа.

---

<a name="english"></a>
## 🇬🇧 English

**NetProbe** is a lightweight, strictly concurrent Go-based network scanning engine and SDK. It is designed to be easily compiled into `.AAR` (Android) or `.framework` (iOS) via `gomobile` for modern VPN clients. 

NetProbe acts as a **Smart QoS (Quality of Service) Engine**. Instead of just checking for blocks, it diagnoses network degradation (like UDP shaping). This allows your VPN client to keep users on battery-friendly, low-latency protocols (like native WireGuard or Hysteria2) when the network is clean, and seamlessly fallback to heavy, battery-draining protocols (like VLESS/Trojan over TCP) *only* when active DPI filtering is detected. All in under 3 seconds.

### 🚀 Key Features

* **Gomobile-Ready:** Built efficiently. The main entrypoint is in `lib/mobile/api.go` which allows seamless compilation using `gomobile bind`. Uses `quic-go` for true UDP/QUIC handshakes.
* **Strict Concurrency:** All network checks run in parallel. The entire scan takes exactly as long as the longest timeout (max 3 seconds).
* **Smart DPI Heuristics:** Detects TLS SNI filtering and unencrypted HTTP Host interception.
* **Protocol-Specific Checks:** 
  * Tests UDP 53 (DNS) vs UDP 443 (QUIC) to determine if protocols like **Hysteria2** or **TUIC** will survive.
  * Tests TCP 443 to fallback to **VLESS/Trojan** if UDP is shaped.
* **DNS Spoofing Detection:** Compares system DNS resolution against trusted DoH providers and validates TLS certificates. Avoids false positives on Geo-CDN networks. Bypasses DNS-hijacking entirely by hardcoding DoH endpoint IPs.
* **Dynamic Clean IP Pool:** Automatically finds a working trusted IP (Cloudflare, Google, Yandex, Quad9) on channels to prevent false-positive DPI detections if a specific provider is blocked.

### 📦 Installation (For Go Developers)

```bash
go get github.com/k0ssk0ss-ai/netprobe/pkg/engine
```

### 🛠 Usage as an SDK (Embedding into VPN Clients)

```go
package main

import (
    "fmt"
    "github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

func main() {
    // 1. Get a dynamically verified clean IP
    cleanIP := engine.GetCleanIP()

    // 2. Run diagnostics
    transportRes := engine.CheckTransport(cleanIP)
    dpiRes := engine.CheckDPI(cleanIP, "twitter.com")
    dnsRes := engine.CheckDNS("twitter.com")

    // 3. Make routing decisions based on network health
    if transportRes.UDP443Works {
        fmt.Println("QUIC is open! Switch to Hysteria2.")
    } else if dpiRes.SNIBlocked {
        fmt.Println("DPI detected! Switch to VLESS+Reality.")
    } else {
        fmt.Println("Clean network. WireGuard is safe to use.")
    }
}
```

### 💻 Standalone & CLI Mode (v2.5+)

NetProbe can be run as a standalone executable. If you run it without arguments, it enters **Standalone Mode**, which sequentially scans a predefined list of popular blocked domains (youtube.com, instagram.com, etc.) and generates a comprehensive `netprobe_report.json` in the same directory. This is perfect for crowdsourcing network metrics from non-technical users.

```bash
# Build the binary
go build -o probe cmd/probe/main.go

# 1. Standalone Mode (Double-click or run without flags)
./probe
# Output: Scans multiple domains and saves to netprobe_report.json

# 2. Single Target CLI Mode
./probe -target=twitter.com

# 3. Start Daemon with Web UI on port 8080
./probe -daemon -target=instagram.com
```

### 🤝 Contributing
Pull requests with new fast, lightweight heuristics are welcome!


---

<a name="русский"></a>
## 🇷🇺 Русский

**NetProbe** — это легковесный, параллельный сетевой движок-сканер и SDK, написанный на Go. Он разработан специально для легкой компиляции в `.AAR` (Android) или `.framework` (iOS) через `gomobile` для встраивания в современные VPN-клиенты.

NetProbe выступает как **умный QoS-движок (Quality of Service)** для мобильных VPN. Вместо банальной проверки доступности портов, он диагностирует деградацию сети (например, скрытый шейпинг UDP). Это позволяет вашему клиенту держать пользователей на легких, экономящих батарею и дающих низкий пинг протоколах (нативный WireGuard, Hysteria2) в чистых сетях, и переключать их на "тяжелые", расходующие батарею TCP-протоколы (VLESS/Trojan) *только* там, где реально работает DPI. И всё это менее чем за 3 секунды.

### 🚀 Ключевые возможности

* **Готовность к Gomobile:** Построен исключительно на стандартной библиотеке Go (`net`, `crypto/tls`) и `miekg/dns`. Никаких тяжелых зависимостей.
* **Строгая многопоточность:** Все сетевые проверки запускаются параллельно. Полное сканирование занимает ровно столько времени, сколько длится самый длинный таймаут (до 3 секунд).
* **Умная DPI-эвристика:** Обнаруживает фильтрацию по TLS SNI и перехват незашифрованного HTTP Host.
* **Специфичные проверки протоколов:** 
  * Сравнивает доступность UDP 53 (DNS) и UDP 443 (QUIC), чтобы понять, выживут ли протоколы вроде **Hysteria2** или **TUIC**.
  * Проверяет TCP 443 для отката на **VLESS/Trojan**, если провайдер "душит" UDP.
* **Детект DNS Spoofing'а:** Сравнивает системный DNS с ответами от доверенных DoH (DNS over HTTPS) и валидирует TLS-сертификаты. Защищен от DNS-хиджакинга благодаря обращению к DoH через хардкодные IP-адреса.
* **Динамический пул чистых IP:** Автоматически находит доступный доверенный IP (Cloudflare, Google, Yandex, Quad9) с помощью каналов, чтобы избежать ложных срабатываний, если какой-то из серверов попал под ковровые блокировки.

### 📦 Установка 

```bash
go get github.com/k0ssk0ss-ai/netprobe/pkg/engine
```

### 🛠 Использование как SDK

```go
package main

import (
    "context"
    "fmt"
    "time"
    "github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

func main() {
    // 1. Создаем контекст с жестким таймаутом (защита для мобильных ОС)
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // 2. Получаем живой "чистый" IP-адрес для тестов
    cleanIP := engine.GetCleanIP(ctx)

    // 3. Запускаем параллельную диагностику
    transportRes := engine.CheckTransport(ctx, cleanIP)
    dpiRes := engine.CheckDPI(ctx, cleanIP, "twitter.com")
    dnsRes := engine.CheckDNS(ctx, "twitter.com")

    // 4. Принимаем решение о выборе VPN-протокола с учетом QoS
    if transportRes.UDP443Works && transportRes.UDPRTTMs < 100 {
        fmt.Println("QUIC открыт, пинг отличный! Идеально для Hysteria2.")
    } else if dpiRes.SNIBlocked || dpiRes.LikelyDPIInjected {
        fmt.Println("Обнаружен активный DPI (Сброс по SNI)! Переключаемся на VLESS+Reality.")
    } else if transportRes.TCPJitterMs > 50 {
        fmt.Println("Канал нестабилен (высокий Jitter). Рекомендуем TCP (OpenVPN/VLESS).")
    } else {
        fmt.Println("Сеть чистая и стабильная. Можно использовать WireGuard.")
    }
}
```

### 📱 Интеграция с Gomobile (Android / iOS)
Для мобильных разработчиков точка входа вынесена в пакет `lib/mobile`. Функция `RunScan(target string) string` оптимизирована под жесткие таймауты ОС (3 секунды) и отдает чистую строку JSON для легкого парсинга в Swift / Kotlin/Java. Скомпилировать SDK невероятно просто: `gomobile bind -target=android ./lib/mobile`.

### 💻 Режим Standalone & CLI (v2.5+)

Вы можете запустить NetProbe как портативную утилиту. Если запустить бинарник без аргументов (двойным кликом), он перейдет в **Standalone Mode**: автоматически проверит список популярных заблокированных доменов (youtube.com, instagram.com и др.) и сохранит подробный отчет в файл `netprobe_report.json` в той же папке. Это идеально подходит для сбора данных о блокировках от обычных пользователей!

```bash
# Сборка
go build -o probe cmd/probe/main.go

# 1. Standalone Режим (Без флагов / двойной клик)
./probe
# Итог: Проверяет список доменов и генерирует netprobe_report.json

# 2. CLI Режим (Проверка одного домена с выводом в консоль)
./probe -target=twitter.com

# 3. Запуск Демона с веб-интерфейсом на порту 8080
./probe -daemon -target=instagram.com
```

### 🤝 Contributing
Мы рады любым Pull Request'ам с новыми быстрыми эвристиками и идеями!
