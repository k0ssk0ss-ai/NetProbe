# NetProbe Donation Collector

Serverless Cloudflare Worker that receives **anonymized** censorship reports from the
"donate a test" button and stores them for the public map.

## Privacy (non-negotiable)

- The client sends only `AnonReport` — **no IPs, no identifiers**, only the censorship
  signal (block method + JA3/JA4 verdicts). See `pkg/engine.Anonymize`.
- The Worker derives **coarse vantage** (country + ASN) from Cloudflare edge metadata and
  **never reads or stores the raw client IP**.
- The Worker is open source, so anyone can verify what is retained.

If this model is ever weakened, it will destroy trust in the whole client — do not.

## Deploy

```bash
cd collector
npm i -g wrangler
wrangler deploy          # creates the Analytics Engine dataset on first deploy
```

Then route it under your domain (behind Cloudflare) — uncomment the `[[routes]]` block in
`wrangler.toml` and set your hostname, e.g. `collector.yourdomain.com/ingest`.

## How the client reaches it (censorship-resistant)

The collector domain itself can be blocked. The client bypasses that:

- It bootstraps the TLS connection to a **hardcoded Cloudflare anycast IP** (any edge IP,
  e.g. `104.16.0.0/13`) using the collector hostname as **SNI**. Cloudflare routes by
  SNI/Host, so the exact IP does not matter and DNS blocking is bypassed.
- Wire it from the app (gomobile) — the two-step, preview-then-send flow:

```
// Step 1 — scan + show the user exactly what will be sent (no upload yet):
preview := mobile.DonatePreview("")   // "" = default domain set

// Step 2 — only after the user taps "send":
res := mobile.DonateSend(preview,
    "https://collector.yourdomain.com/ingest",
    "104.16.132.229",                 // hardcoded CF edge IP (bootstrap)
    "collector.yourdomain.com")       // SNI
```

## Payload shape

```jsonc
{
  "schema_version": 1,
  "reports": [
    {
      "target": "twitter.com",
      "sni_blocked": true,
      "tls_blocked": true,
      "block_method": "TCP RST",
      "udp_443_works": false,
      "fingerprints": [ { "ja3": "...", "ja4": "t13d...", "verdict": "RST" } ]
    }
  ]
}
```

## The map (the flywheel)

Query Analytics Engine (GraphQL/SQL API) → render a public real-time map of *what is
blocked where, by which method, right now*. The map draws users → more donations → a
sharper map. That data moat is what makes integrators want to embed NetProbe.
