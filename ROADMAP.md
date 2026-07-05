# NetProbe Roadmap — v3 "Survivability Engine"

> Status: planning. This document is the working plan for turning NetProbe from a
> connectivity probe into an embeddable decision engine that VPN clients can rely on
> to pick a *working* protocol/transport/fingerprint automatically.

## 1. Why v3 exists (the reframe)

A 3-second network probe is a commodity — any client developer can write one. NetProbe
is only worth embedding if it provides something an integrator **cannot cheaply rebuild
alone**. That is not the probe code; it is:

1. **A decision** — not "SNI is blocked", but "use *this* outbound, with fingerprint
   `firefox` on port `48443`, because chrome ClientHello is being RST'd here."
2. **A maintained corpus** — validated DPI / block-page / fingerprint signatures.
3. (later) **A shared map** — real-time cross-user interference telemetry.

v3 focuses on **(1)** for **client developers (Vector A)**, keeps **Vector C** (operator
canary) as a fast-follow reusing the same engine, and lays a **scaffold-only** seed for
**Vector B** (telemetry) without building the network yet.

### The motivating case

A user had a fully working VLESS key that "just didn't connect." Nothing was wrong with
the key, the server, or the SNI — the ISP was blocking the **shape of the TLS ClientHello**
(the uTLS `chrome` fingerprint / its JA3). Switching the client's fingerprint to `firefox`
fixed it instantly. Classic probes never see this. v3's headline capability automates
exactly this manual debugging.

## 2. Core concept — the Survivability Matrix

The engine's new primitive is not a boolean "blocked / not blocked" but a **matrix of
survivability** over `{transport × port × uTLS fingerprint × SNI}`: which combinations
complete a handshake, which get RST-injected, which fall into a blackhole.

The same matrix feeds all three vectors:

- **Vector A** — matrix + the client's available outbounds → a ranked decision.
- **Vector C** — the matrix run periodically against operator-defined endpoints → health report.
- **Vector B (seed)** — the anonymized matrix (JA3 hashes + block method only, never keys) → optional sink.

One engine, three consumers.

## 3. Architecture decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| Client ecosystem | **Client-agnostic core** + first adapter = **sing-box**; Xray-core fast-follow | Don't lock out forks; sing-box is the largest modern forkbase with a clean outbound model and Reality/uTLS support |
| Fingerprint depth (Phase 1) | **Full matrix + JA3/JA4, time-budgeted** | "Optimality *and* speed": probe all profiles concurrently, early-exit for the decision, collect the full matrix when within the 3s budget |
| First consumer | **Vector A (client developers)** | Highest adoption potential; C reuses the same engine later |
| Telemetry (Vector B) | **Scaffold only, opt-in, off by default** | Telemetry in a privacy tool is radioactive; build the seam, not the network |

## 4. Components

### `pkg/engine` — lightweight core (no GUI)
- **Refactor existing:** `transport`, `dpi`, `dns`, `resolver`, `qos`.
  - Fix: QUIC test hardcodes `1.1.1.1` instead of the resolved `cleanIP`.
  - Harden: heuristics currently match on error strings — move toward structured classification.
- **NEW `fingerprint`** ⭐ — built on `github.com/refraction-networking/utls`.
  Crafts ClientHellos for a set of profiles (chrome, firefox, safari, iOS, edge,
  randomized), attempts handshakes toward a target, classifies the outcome
  (`PASS` / `RST` / `BLACKHOLE` / `OTHER`), and computes the **JA3/JA4** of what it sent.
  - *Fast mode:* against a clean host — catches coarse JA3 filtering.
  - *Accurate mode:* against the user's real endpoint/SNI — catches the motivating case.
- **NEW `decision`** (Vector A core) — input: probe results + outbound candidate
  descriptors; output: a ranked decision with a human-readable reason.

### `pkg/canary` — Vector C (fast-follow)
Client-side endpoint health reporter to an operator-defined server. Reports from the
**user's vantage point**, which server-side monitoring cannot see.

### `pkg/telemetry` — Vector B (scaffold only)
`TelemetrySink` interface + local buffer + anonymization. **Off by default, strict opt-in.**
No backend now — just the seam so the network can be added later without re-architecting.

### Integration surface — **the real product**
- Versioned JSON schema: `NetworkInterferenceReport` + `Decision` (Swift/Kotlin parse this).
- `lib/mobile` — gomobile bindings over the schema.

### `cmd`
- CLI/daemon for testing and as a minimal self-host canary.
- **Move GUI (`cmd/app` + Fyne) into a separate module** so `go get pkg/engine` stays light.

## 5. The output contract (schema v1 sketch)

This is the product surface for integrators. Freeze it early; version it.

```jsonc
{
  "schema_version": 1,
  "timestamp": "2026-07-03T12:00:00Z",
  "target_host": "example.com",
  "vantage": { "asn": null, "country": null },      // filled only if telemetry opt-in
  "transport": {
    "tcp443_open": true,
    "udp53_works": true,
    "udp443_works": false,
    "udp_shaped": true,
    "tcp_rtt_avg_ms": 34.2,
    "tcp_jitter_ms": 8.1
  },
  "dpi": {
    "sni_blocked": true,
    "http_blocked": false,
    "block_method": "TCP RST",
    "likely_injected": true
  },
  "dns": {
    "spoofing_detected": false,
    "doh_success": true,
    "resolved_ips": ["93.184.216.34"]
  },
  "fingerprint_matrix": [
    { "profile": "chrome",  "ja3": "cd08...", "ja4": "t13d...", "verdict": "RST",  "rtt_ms": 41 },
    { "profile": "firefox", "ja3": "b32c...", "ja4": "t13d...", "verdict": "PASS", "rtt_ms": 55 }
  ],
  "decision": {
    "chosen_outbound_id": "vless-reality-01",
    "overrides": { "fingerprint": "firefox", "port": 48443 },
    "reason": "chrome ClientHello is RST-injected on this ISP; firefox survives",
    "alternatives": ["vless-reality-02"]
  },
  "recommendations": ["[PROTOCOL] SNI filtering active. Prefer VLESS+Reality with firefox fingerprint."]
}
```

## 6. Vector A — the decision engine (Phase 2 focus)

- **Input:** `[]OutboundCandidate { id, protocol, transport, port, sni, fingerprint, dest_ip }`
  — neutral descriptors, ecosystem-independent.
- **Process:** for each candidate, probe reachability + transport + fingerprint survivability
  against its `(dest_ip, port, sni, fingerprint)`.
- **Output:** ranked `Decision` with `overrides` (the parameters to change, e.g. fingerprint/port)
  and a `reason`.
- **Adapters:** `singbox` (first) maps sing-box outbound JSON ⇄ `OutboundCandidate`; `xray` fast-follow.
- **Constraint:** the core must never import a client's types. Adapters live outside the core.

## 7. Vector C — operator canary (fast-follow)

Reuses `pkg/engine`. Operator supplies a list of their endpoints; the client runs the
matrix on a schedule and POSTs results to an operator-owned collector. No shared/public
backend involved — the operator owns their data.

## 8. Vector B — telemetry seed (scaffold only)

Ship only the `TelemetrySink` seam + anonymization + local buffering. If/when adoption
justifies a network, the privacy model must be **demonstratively paranoid**:
- opt-in, default OFF; no identifiers; aggregate to ASN/region; k-anonymity;
- prefer "share this result" on explicit user tap over silent background collection;
- open telemetry protocol and open collector, so anyone can audit what leaves the device.

A single "NetProbe phones home" incident kills trust in A and C too. Do not compromise here.

## 9. Phased plan

| Phase | Goal | Key deliverables | Done when |
|---|---|---|---|
| **0 — Foundation** ✅ | Solid base | Fix QUIC `cleanIP` bug; clean repo (drop `probe.exe`, report, drafts); split Fyne into a separate module; **freeze schema v1** | `go get pkg/engine` pulls no GUI deps; schema documented |
| **1 — Fingerprint probe** ⭐ 🟢 core | The differentiator | `pkg/engine/fingerprint` with uTLS matrix, ~~JA3/JA4~~, fast+~~accurate~~ modes, concurrent + time-budgeted | Correctly flags chrome-RST / firefox-PASS on a censored path within 3s |
| **2 — Decision engine (A)** ✅ core | Turn probe into a choice | `pkg/engine/decision` + `OutboundCandidate` + sing-box adapter; `decision` block in schema; wired into CLI (`-config`) & mobile (`RunScanWithConfig`) | Given N candidates, returns a ranked working choice with overrides |

> **Progress (2026-07-05):** Phase 0 done. Phase 1 core done (survivability matrix live & smoke-tested); JA3/JA4 population remains. Phase 2 core done (decision engine + sing-box adapter, 10 unit tests incl. the chrome→firefox case, wired end-to-end).
>
> **Accurate-mode fixes (field-validated on a live RU ISP, 2026-07-05):** A real-network run exposed three false readings, all rooted in probing generic/clean targets instead of the real destination — now fixed:
> 1. **False "clean"** — DPI SNI test + fingerprint matrix now hit the target's REAL IP (resolved via DoH), catching destination-aware RST/blackhole that a clean-IP probe missed (e.g. Discord/YouTube read as clean while actually blocked).
> 2. **DNS-spoofing mislabel** — RST/timeout on the real IP is now labelled `tls_blocked` (DPI/IP filtering), not `spoofing_detected` (which is reserved for genuine wrong-cert interception).
> 3. **UDP false-negative** — the strategy no longer equates "QUIC-to-public-CDN-on-443 throttled" with "UDP dead"; it cross-checks STUN RTT and stops advising working custom-port Hysteria/WireGuard users to switch to TCP.
> 4. **DPI classifier consistency** — a second field run showed `dpi.sni_blocked=false` while the matrix/tls_blocked said "blocked", caused by (a) a dial timeout treated as a non-block and (b) the Windows RST wording (`forcibly closed`) not matched. The DPI module now reuses the shared `classifyFingerprintErr`, so a failed connect and Windows RST both classify as a block.
>
> **Field-confirmed (2026-07-05):** a third run shows all layers consistent per domain — youtube/telegram blackholed, instagram/twitter actively RST-injected (`likely_dpi_injected`), discord.com landing genuinely reachable via CDN, no false spoofing, UDP correctly exonerated. Accurate-mode closed.
>
> **Follow-up batch (2026-07-05):** four polish items landed, all build/test-green:
> 1. **Scan speed** — destination-facing TLS probes (matrix, DPI, DNS verify) are now capped at a 2s per-probe timeout, so blackholed domains no longer burn the full ~5s deadline.
> 2. **App-level reachability** — `CheckEndpoints` probes an app's critical secondary endpoints (Discord: `gateway.discord.gg`, `cdn.discordapp.com`) against their real IPs; `endpoints` block + an `[APP]` recommendation now flag "landing loads but the app is dead".
> 3. **JA3** — the matrix now emits the JA3 fingerprint (MD5) of each ClientHello it sends, with GREASE filtering, for shareable telemetry (unit-tested). JA4 still pending.
> 4. **Vector A accurate mode** — `DecideOutboundActive` actively probes each candidate against ITS OWN endpoint IP + SNI (not the diagnostic target), wired into CLI `-config` and mobile `RunScanWithConfig`.
>
> **Closing batch (2026-07-05):** field-validated Vector A end-to-end (same config → Hysteria when clean, Reality when SNI-blocked). Then landed:
> - **JA4** — shuffle-resistant fingerprint (FoxIO spec, unit-tested; pending cross-validation vs reference vectors) alongside JA3.
> - **`randomized` dropped** from the default matrix (noise; clients set a concrete fingerprint).
> - **Vector B seed** — `TelemetrySink` + `Anonymize` (censorship signal only, no IPs/identifiers), OFF by default, no network. Unit-tested for no-leak + opt-in-only.
> - **`-out` flag** + status line moved to stderr (clean JSON file even with redirect); diagnosed the PowerShell `-flag=value.with.dots` mangling (quote the args).
>
> **Vector B activated (2026-07-05):** "donate a test" pipeline built end-to-end for a **Hiddify** fork.
> - Client: `RunDonation` (parallel multi-domain scan → `[]AnonReport`), `HTTPSink` (POST with hardcoded-CF-IP bootstrap so a blocked collector domain can't stop delivery), mobile `DonatePreview`/`DonateSend` (two-step preview→confirm, privacy-first). Unit-tested.
> - Server: `collector/` — Cloudflare Worker that derives coarse vantage (country/ASN) from CF metadata, **never stores raw IP**, writes to Analytics Engine. Open source + README.
>
> - Desktop: `cmd/app` (Fyne) rebuilt as the reference opt-in flow — **RUN TEST (preview)** runs `RunDonation` and shows the exact anonymized payload; **DONATE TO SERVER** uploads via `HTTPSink` only after the user reviews it (disabled until a collector is configured). Preview-only + copy-out works with no server.
>
> **Remaining (product/hands-on, not pure engine code):** the actual Hiddify fork integration (gomobile-bind, add the button, wire the two calls, deploy the Worker); the public map UI over Analytics Engine; UDP/voice probing (still deliberately skipped); cross-ISP validation.
| **3 — Canary (C)** | First operator value | `pkg/canary` + reference collector | Self-hoster sees per-endpoint health from user vantage |
| **4 — Telemetry seed (B)** | Future-proof the seam | `TelemetrySink` + anonymization, off by default | Anonymized report can be emitted to a local sink; no PII |
| **5 — Integration proof** | Prove embeddability | One real integration into a live client fork + schema docs + `lib/mobile` update | A fork ships protocol/fingerprint auto-selection powered by NetProbe |

## 10. Definition of "8/10"

A user with a working-but-not-connecting VLESS key taps connect. In ~3s NetProbe finds
that `chrome` gets RST while `firefox` passes, the decision engine returns "use this
outbound, fingerprint=firefox", and the client connects on the first try — silently. The
client developer embedded NetProbe because building this matrix + decision themselves is
not worth it. That is the bar.

## 11. Risks

- **uTLS is a non-trivial dependency** — but it *is* the feature, unlike the Fyne balast.
- **Accurate-mode probing hits the user's real endpoint** — mind timeouts and avoid looking
  like an active scanner to the destination.
- **Decision engine coupling** — if it hard-binds to sing-box types, Xray forks are lost.
  Keep the core neutral; adapters on top.
- **Vector B is a landmine** — scaffold now, but never enable collection without the
  paranoid privacy model above.
