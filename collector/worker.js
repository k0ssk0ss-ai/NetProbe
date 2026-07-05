// NetProbe donation collector — Cloudflare Worker (reference implementation).
//
// PRIVACY MODEL (see ROADMAP.md §8 — telemetry in a privacy tool is a landmine):
//   * Derives ONLY coarse vantage (country + ASN) from Cloudflare edge metadata.
//   * NEVER reads or stores the client's raw IP.
//   * Stores only the anonymized censorship signal the client already stripped.
//   * Open source, so anyone can verify what is retained.
//
// The client (pkg/engine HTTPSink) bootstraps to a hardcoded Cloudflare IP with the
// collector's SNI, so a blocked collector domain cannot stop delivery.

export default {
  async fetch(request, env) {
    if (request.method === "GET") {
      return json({ service: "netprobe-collector", ok: true });
    }
    if (request.method !== "POST") {
      return json({ error: "method not allowed" }, 405);
    }

    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ error: "invalid json" }, 400);
    }

    const reports = Array.isArray(payload?.reports) ? payload.reports : [];
    if (reports.length === 0) {
      return json({ error: "no reports" }, 400);
    }

    // Coarse vantage from Cloudflare — the raw client IP is intentionally never read.
    const cf = request.cf || {};
    const vantage = {
      country: cf.country || "XX",
      asn: cf.asn ? Number(cf.asn) : 0,
      as_org: cf.asOrganization || "",
    };
    const receivedAt = new Date().toISOString();

    // Store each report with server-derived vantage. Analytics Engine is cheap, keeps no
    // PII, and is queryable for the public map. Swap for D1/KV if you prefer SQL.
    if (env.NETPROBE_AE) {
      for (const r of reports.slice(0, 50)) {
        env.NETPROBE_AE.writeDataPoint({
          indexes: [String(vantage.asn)],
          blobs: [
            vantage.country,
            vantage.as_org,
            String(r.target || ""),
            String(r.block_method || ""),
            JSON.stringify(r.fingerprints || []),
            receivedAt,
          ],
          doubles: [
            r.sni_blocked ? 1 : 0,
            r.tls_blocked ? 1 : 0,
            r.udp_443_works ? 1 : 0,
          ],
        });
      }
    }

    return json({ ok: true, accepted: reports.length, vantage });
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
