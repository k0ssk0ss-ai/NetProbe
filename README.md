# NetProbe — network interference diagnostics & protocol-selection engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English](#english) | [Русский](#русский)

> [!WARNING]
> **Beta / experimental.** The heuristics have been field-validated on a *single* ISP so
> far. Expect false positives and tuning across different providers and censorship setups.
> Not audited. See [ROADMAP.md](ROADMAP.md) for what is done vs. pending.

---

<a name="english"></a>
## 🇬🇧 English

NetProbe is a small Go engine that diagnoses **how** a network path is being interfered
with — and, given a client's proxy config, picks an outbound that actually gets through.
It's built to compile into an Android/iOS binding (`gomobile`) and embed into VPN clients.

The core idea: most clients pick a *server* by latency, but not a *protocol/transport/
fingerprint* by the censorship method in play. NetProbe measures the method, then decides.

### What it actually does

- **Accurate-mode probing.** DPI, DNS and the fingerprint matrix probe the target's **real
  IP** (resolved via DoH, bypassing DNS hijacking), so destination-aware blocking (an RST
  or blackhole on the real host) is caught instead of being reported as "clean".
- **Survivability Matrix.** Sends several uTLS ClientHello fingerprints (Chrome, Firefox,
  Safari, iOS, Edge) and reports which survive — automating the manual "switch Chrome→
  Firefox until it connects" debugging. Emits JA3 and JA4 per profile.
- **Decision engine (Vector A).** Given the user's outbounds, ranks them under the observed
  conditions and returns the one to use plus client-tunable overrides (fingerprint,
  fragment, port, SNI, dial IP). Server-bound fields (uuid, keys, flow) are never touched.
- **Config adapters.** Parses **sing-box** and **Xray** configs into a neutral model
  (auto-detected).
- **Honest transport read.** Distinguishes "standard QUIC-to-CDN throttled" from "UDP is
  dead" using a STUN cross-check — so a working custom-port Hysteria setup isn't wrongly
  told to fall back to TCP.
- **Opt-in donation pipeline.** A user-initiated "donate a test" flow (preview → confirm)
  that uploads only an anonymized signal (no IPs, no identifiers) to a collector.

### Install

```bash
go get github.com/k0ssk0ss-ai/netprobe/pkg/engine
```

The core module pulls only `miekg/dns`, `quic-go` and `utls` — no GUI dependencies.

### SDK usage

```go
import (
    "context"
    "time"

    "github.com/k0ssk0ss-ai/netprobe/pkg/engine"
    "github.com/k0ssk0ss-ai/netprobe/pkg/adapter"
)

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// 1. Diagnose a target.
report := engine.RunEngineScans(ctx, "twitter.com")
// report.Results.DPI.SNIBlocked, report.FingerprintMatrix, report.Recommendations ...

// 2. Decide which outbound to use (Vector A), from the user's sing-box/Xray config.
candidates, _ := adapter.Parse(userConfigJSON)
decision := engine.DecideOutboundActive(ctx, report, candidates)
// decision.ChosenOutboundID, decision.Overrides.Fingerprint, decision.Reason
```

### CLI

```bash
go build -o probe ./cmd/probe

./probe                                   # standalone: scans a domain list -> netprobe_report.json
./probe -target=twitter.com               # single target -> JSON on stdout
./probe -target=twitter.com -config=c.json -out=r.json   # + decision, clean JSON to file
```

> On PowerShell, quote flags whose values contain a dot: `.\probe.exe "-target=twitter.com"`.

### Embedding into a client

See [integration/](integration/) for the gomobile binding scripts and a worked
Hiddify-style integration (donate button + decision engine), with the layers spelled out.

### Limitations (read these)

- Validated on one ISP; cross-provider tuning is pending.
- App-level reachability is partial: e.g. Discord gateway/CDN are probed, but voice (UDP to
  dynamic IPs) is not.
- JA4 follows the FoxIO spec but is not yet cross-validated against reference vectors.
- iOS binding requires macOS + Xcode + an Apple Developer account.

---

<a name="русский"></a>
## 🇷🇺 Русский

NetProbe — небольшой Go-движок, который диагностирует, **как именно** сеть вмешивается в
трафик, и — по конфигу клиента — выбирает аутбаунд, который реально проходит. Собирается в
Android/iOS-биндинг через `gomobile` для встраивания в VPN-клиенты.

Идея: клиенты обычно выбирают *сервер* по пингу, но не *протокол/транспорт/fingerprint* по
методу цензуры. NetProbe меряет метод и на его основе принимает решение.

### Что он делает на самом деле

- **Accurate-режим.** DPI, DNS и fingerprint-матрица бьют в **реальный IP** цели (резолв
  через DoH, мимо DNS-хиджака), поэтому адресная блокировка (RST/blackhole на настоящем
  хосте) ловится, а не выдаётся за «чисто».
- **Survivability Matrix.** Шлёт несколько uTLS-fingerprint'ов (Chrome, Firefox, Safari,
  iOS, Edge) и показывает, какие выживают — автоматизация ручного «переключай Chrome→
  Firefox, пока не подключится». Считает JA3 и JA4 на каждый профиль.
- **Движок решений (Vector A).** По аутбаундам пользователя ранжирует их под наблюдаемые
  условия и выдаёт, какой использовать, плюс client-tunable оверрайды (fingerprint,
  фрагментация, порт, SNI, dial IP). Серверные поля (uuid, ключи, flow) не трогает.
- **Адаптеры конфигов.** Парсит **sing-box** и **Xray** в нейтральную модель (авто-детект).
- **Честная оценка транспорта.** Отличает «стандартный QUIC-к-CDN зашейплен» от «UDP мёртв»
  через STUN-сверку — рабочую Hysteria на кастомном порту не гонит зря на TCP.
- **Opt-in донат.** Флоу «пожертвовать тест» (превью → подтверждение) грузит на коллектор
  только обезличенный сигнал — без IP и идентификаторов.

### Установка

```bash
go get github.com/k0ssk0ss-ai/netprobe/pkg/engine
```

Ядро тянет только `miekg/dns`, `quic-go`, `utls` — без GUI-зависимостей.

### Использование как SDK

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

report := engine.RunEngineScans(ctx, "twitter.com")

candidates, _ := adapter.Parse(userConfigJSON)   // sing-box или Xray
decision := engine.DecideOutboundActive(ctx, report, candidates)
// decision.ChosenOutboundID, decision.Overrides.Fingerprint, decision.Reason
```

### CLI

```bash
go build -o probe ./cmd/probe
./probe                         # скан списка доменов -> netprobe_report.json
./probe -target=twitter.com     # один домен -> JSON в stdout
./probe -target=twitter.com -config=c.json -out=r.json   # + решение, чистый JSON в файл
```

> В PowerShell квотируй флаги с точкой в значении: `.\probe.exe "-target=twitter.com"`.

### Встраивание в клиент

См. [integration/](integration/) — скрипты gomobile-биндинга и разобранная интеграция в духе
Hiddify (кнопка доната + движок решений), со всеми слоями.

### Ограничения (важно)

- Проверено на одном провайдере; настройка под другие — впереди.
- Доступность приложений покрыта частично: у Discord пробиваются gateway/CDN, но не voice
  (UDP на динамические IP).
- JA4 сделан по спецификации FoxIO, но пока не сверен с референс-векторами.
- iOS-биндинг требует macOS + Xcode + Apple Developer.

### Contributing

PR с быстрыми лёгкими эвристиками и адаптерами под новые клиенты приветствуются. Данные с
реальных провайдеров (через донат) — самое ценное.
