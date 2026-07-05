# Integrating NetProbe into a VPN client

This is a worked reference for embedding NetProbe's engine into a gomobile-based client
(e.g. a Hiddify fork). It is deliberately honest about the layers involved — there is no
one-click path, but each step is small.

## What the engine exposes (`lib/mobile`)

Four functions, all `string`-in / `string`-out (gomobile-friendly):

| Function | Purpose |
|---|---|
| `RunScan(target) string` | Diagnose one domain → JSON `ProbeReport`. |
| `RunScanWithConfig(target, configJSON) string` | Diagnose + pick the best outbound from the user's config (Vector A). Accepts sing-box **or** Xray JSON (auto-detected). |
| `DonatePreview(domainsCSV) string` | Scan a set of domains → JSON `[]AnonReport`. **Sends nothing.** Show this to the user. |
| `DonateSend(previewJSON, endpoint, bootstrapIP, sni) string` | Upload the previewed reports to the collector. Call only after the user confirms. |

## 1. Build the binding

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init
```

Then, from the repo root:

- **Android** (needs the Android NDK):
  ```bash
  ./integration/bind.sh android   # -> netprobe.aar
  ```
- **iOS** (needs macOS + Xcode + an Apple Developer account for signing):
  ```bash
  ./integration/bind.sh ios       # -> NetProbe.xcframework
  ```

If your client already embeds a Go core (Hiddify does), the simplest path is to add
`github.com/k0ssk0ss-ai/netprobe/lib/mobile` to *that* module's bind target instead of
shipping a second `.aar`.

## 2. Bridge to the UI

The binding is native (Kotlin/Swift). A Flutter app (Hiddify) reaches it via a
`MethodChannel` — the engine cannot be called from Dart directly. The chain is:

```
Dart (button) ──MethodChannel──► Kotlin/Swift ──► gomobile ──► NetProbe (Go)
```

**Kotlin side** (Android):
```kotlin
import netprobe.Netprobe   // gomobile-generated package (lowercased module name)

class NetProbeBridge(flutterEngine: FlutterEngine) {
    private val channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "netprobe")

    init {
        channel.setMethodCallHandler { call, result ->
            when (call.method) {
                "donatePreview" -> result.success(Netprobe.donatePreview(call.argument("domains") ?: ""))
                "donateSend" -> result.success(
                    Netprobe.donateSend(
                        call.argument("preview") ?: "",
                        call.argument("endpoint") ?: "",
                        call.argument("bootstrapIP") ?: "",
                        call.argument("sni") ?: ""
                    )
                )
                else -> result.notImplemented()
            }
        }
    }
}
```

**Dart side** (the donate button):
```dart
const _channel = MethodChannel('netprobe');

// Step 1 — scan and show the user exactly what will be sent (no upload yet).
final previewJson = await _channel.invokeMethod<String>('donatePreview', {'domains': ''});
final preview = jsonDecode(previewJson!);
final agreed = await showDonationPreviewDialog(preview);   // your UI: render the JSON

// Step 2 — only if the user tapped "send".
if (agreed) {
  final res = await _channel.invokeMethod<String>('donateSend', {
    'preview': previewJson,
    'endpoint': 'https://collector.yourdomain.com/ingest',
    'bootstrapIP': '104.16.132.229',   // any Cloudflare edge IP (bootstrap past DNS blocking)
    'sni': 'collector.yourdomain.com',
  });
}
```

## 3. Non-negotiable UX rules

- The button is **opt-in and off by default**. Nothing leaves the device unprompted.
- **Show the `DonatePreview` JSON to the user before sending.** It contains no IPs or
  identifiers (see `engine.Anonymize`), and letting the user see that is what earns trust
  in an anti-censorship tool.
- The collector (`collector/`) derives coarse vantage (country/ASN) server-side and never
  stores the raw IP.

## 4. Using the decision engine (Vector A)

To auto-pick a working outbound, pass the user's active config to `RunScanWithConfig`:

```kotlin
val reportJson = Netprobe.runScanWithConfig("twitter.com", userConfigJson)
// reportJson.decision → { chosen_outbound_id, overrides {fingerprint, port, ...}, reason }
```

Apply `decision.overrides` to the chosen outbound (e.g. set the uTLS fingerprint) before
connecting. Only client-tunable fields are ever suggested — never server-bound ones.

## Honest limitations

- Heuristics are validated on a single ISP so far; expect tuning across providers.
- iOS requires Apple hardware/accounts — there is no way around this.
- Discord-style voice (UDP to dynamic IPs) is not probed; only gateway/CDN reachability is.
