# ws-tcp-bridge-worker

A generic **WebSocket-to-TCP bridge** as a single Cloudflare Worker. Browser clients can't open raw TCP sockets; this Worker forwards a WebSocket to any allowlisted TCP destination, letting browser code reach legacy TCP services (SFTP, raw SSH, message brokers, etc.) with end-to-end encryption at the application layer handled by the client.

## Why this exists

Browser security forbids raw TCP. Existing options require either a container running something like [chisel](https://github.com/jpillora/chisel) behind a reverse proxy, or proprietary cloud tunneling (AWS IoT Secure Tunneling). This bridge is ~60 lines of TypeScript, deploys in seconds with `wrangler deploy`, auto-scales to zero, and costs $5/mo base plus pennies for traffic.

**The bridge is protocol-agnostic** — it sees opaque ciphertext if the client speaks SSH/TLS end-to-end. It is not a proxy; it is a pipe.

## Security model

- **HMAC-signed URLs.** Every connection includes `?dest=<host:port>&exp=<unix>&sig=<hex>`. Signature binds to BOTH dest and exp, so a leaked URL is scoped to one destination for its remaining TTL.
- **Destination allowlist (optional).** If `ALLOWED_DESTS` contains one or more `host:port` entries, only those destinations are reachable. If `ALLOWED_DESTS` is empty (the default), **all destinations are allowed** — the HMAC signature is the only gate. Use this mode when the set of destinations isn't known ahead of time.
- **Metadata-only logs.** The Worker logs `{timestamp, dest, cf_ray}` — never payload bytes, never URL params (which contain the HMAC), never auth errors that reflect server banner strings.
- **No Worker-side TLS.** `secureTransport: "off"` — the Worker passes raw bytes. End-to-end cryptography is the client's job.

**Threat not mitigated: egress IP stability.** Cloudflare Workers' outbound TCP egresses from a prefix that is NOT on Cloudflare's published IP ranges and can rotate between PoPs. If your target destination requires source-IP allowlisting, options are:

1. Ask the destination operator to allowlist by credentials only.
2. Add Cloudflare [Dedicated Egress IPs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/egress-policies/) (Zero Trust add-on, paid).
3. For one specific uncooperative destination, fall back to a chisel-on-container bridge with a stable IP you control.

## Signed URL scheme

```
wss://bridge.example.com/?dest=<host:port>&exp=<unix-seconds>&sig=<hex>
```

Where `sig = HMAC-SHA256(HMAC_SECRET, "<dest>|<exp>")`.

The pipe character is a literal `|`. Both components are used verbatim in the signed payload; hostnames can't contain `|` and decimal integers can't either, so there's no ambiguity.

### Signing in a browser (reference code)

Copy-paste into your client app. Keep `HMAC_SECRET` server-side-only — reveal to the browser only from inside a trusted context (e.g. an authenticated backend endpoint that signs and returns the full URL, or a short-lived client-side secret injected during session boot).

```ts
async function signBridgeUrl(
  bridgeBaseUrl: string,           // "wss://bridge.example.com"
  hmacSecret: string,
  dest: string,                    // "sftp.example.com:22"
  ttlSeconds = 300                 // 5 min — don't go longer
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(hmacSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${dest}|${exp}`)
  );
  const sigHex = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const url = new URL(bridgeBaseUrl.replace(/^wss?/, "https"));
  url.searchParams.set("dest", dest);
  url.searchParams.set("exp", String(exp));
  url.searchParams.set("sig", sigHex);
  return url.toString().replace(/^https?/, "wss");
}
```

See `client-example/index.html` for a runnable example.

## Deployment

1. Install: `npm install`
2. Authenticate: `wrangler login`
3. Set the HMAC secret for staging: `wrangler secret put HMAC_SECRET --env staging`
4. (Optional) Set the allowlist: edit `wrangler.toml` → `vars.ALLOWED_DESTS = "sftp.example.com:22,..."`, or set via dashboard. Leave empty to allow all destinations (HMAC-only auth).
5. Deploy: `npm run deploy:staging` (or `deploy:prod`).

Per-destination kill switch (when allowlist is in use): remove an entry from `ALLOWED_DESTS` and redeploy. Clients get an immediate `403 destination not allowed`.

## Observability

- `console.log` in the Worker writes to [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/). Configure sample rate via `[observability]` in `wrangler.toml`.
- Per-destination counters via Cloudflare Analytics Engine — not enabled by default; add a binding if you need it.
- Workers Alerts for error-rate spikes: set up in the Cloudflare dashboard.

## Tests

`npm test` runs the HMAC signing/verification unit tests (`src/hmac.test.ts`) in Node's vitest environment — these exercise the signed-URL cryptography. The Worker `fetch` handler requires a real Cloudflare runtime to fully exercise (outbound TCP, WebSocket pair); test it end-to-end via `wrangler dev` against a local SFTP container.

## Caveats & things to watch

- **Port blocklist.** Cloudflare blocks outbound TCP on port 25 (SMTP). All other common ports (22, 443, 3306, 5432, 6379, etc.) work.
- **WebSocket message size limit.** 32 MiB per message (Cloudflare Workers limit). SSH packets are typically < 32 KB, so this is a non-issue for SFTP but worth noting for other protocols.
- **Long idle sessions.** For sessions lasting several minutes with no active byte flow, verify behavior empirically. If Worker CPU-time limits become an issue, migrate to Durable Objects with the WebSocket Hibernation API.
