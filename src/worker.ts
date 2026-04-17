/**
 * WebSocket-to-TCP bridge — Cloudflare Worker.
 *
 * Auth: supports two mechanisms (configure one or both via env vars):
 *   1. JWT/OAuth — pass `?token=<jwt>`, validated against a JWKS endpoint.
 *      Configure: JWKS_URL, JWT_ISSUER, optionally JWT_AUDIENCE.
 *   2. HMAC-signed URLs — pass `?sig=<hex>&exp=<unix>`, validated against
 *      a shared secret. Configure: HMAC_SECRET.
 *
 * If both are configured, the Worker tries JWT first (if `?token=` is
 * present), then falls back to HMAC.
 *
 * Destination allowlist is optional. If ALLOWED_DESTS is non-empty, only
 * those host:port pairs are reachable. If empty, all destinations are
 * allowed and the auth mechanism is the sole access control.
 */

import { connect } from "cloudflare:sockets";
import { verifySignedUrl } from "./hmac";
import { verifyJwt } from "./jwt";

export interface Env {
  HMAC_SECRET?: string;
  ALLOWED_DESTS: string;
  JWKS_URL?: string;
  JWT_ISSUER?: string;
  JWT_AUDIENCE?: string;
  JWT_REQUIRED_PROFILE?: string; // e.g. "Practitioner/" — rejects tokens whose `profile` claim doesn't start with this
}

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected websocket", { status: 400 });
    }

    const url = new URL(req.url);
    const dest = url.searchParams.get("dest") ?? "";
    if (!dest) {
      return new Response("missing dest", { status: 400 });
    }

    // --- Auth ---
    const token = url.searchParams.get("token");
    let authSubject: string | undefined;

    if (token && env.JWKS_URL) {
      const claims = await verifyJwt(token, env.JWKS_URL, env.JWT_ISSUER, env.JWT_AUDIENCE);
      if (!claims) return new Response("invalid or expired token", { status: 401 });
      if (env.JWT_REQUIRED_PROFILE) {
        const profile = String(claims.profile ?? "");
        if (!profile.startsWith(env.JWT_REQUIRED_PROFILE)) {
          return new Response("insufficient role", { status: 403 });
        }
      }
      authSubject = String(claims.sub ?? "unknown");
    } else if (env.HMAC_SECRET) {
      const sig = url.searchParams.get("sig") ?? "";
      const expRaw = url.searchParams.get("exp") ?? "";
      const exp = parseInt(expRaw, 10);
      if (!Number.isFinite(exp)) return new Response("bad exp", { status: 400 });
      if (!(await verifySignedUrl(env.HMAC_SECRET, dest, exp, sig))) {
        return new Response("unauthorized", { status: 401 });
      }
    } else {
      return new Response("no auth method configured", { status: 500 });
    }

    // --- Allowlist ---
    const allowlist = parseAllowlist(env.ALLOWED_DESTS);
    if (allowlist.size > 0 && !allowlist.has(dest)) {
      return new Response("destination not allowed", { status: 403 });
    }

    const parsed = parseHostPort(dest);
    if (!parsed) {
      return new Response("malformed destination", { status: 400 });
    }

    let socket: Socket;
    try {
      socket = connect({
        hostname: parsed.host,
        port: parsed.port,
        secureTransport: "off" as any,
      } as any);
    } catch (err) {
      return new Response(`tcp connect failed: ${(err as Error).message}`, {
        status: 502,
      });
    }

    const pair = new WebSocketPair();
    const [clientWS, serverWS] = Object.values(pair) as [WebSocket, WebSocket];
    serverWS.accept();

    pipeBytes(serverWS, socket);

    const logEntry: Record<string, unknown> = {
      t: Date.now(),
      dest,
      cf_ray: req.headers.get("cf-ray") ?? null,
    };
    if (authSubject) logEntry.sub = authSubject;
    console.log(JSON.stringify(logEntry));

    return new Response(null, { status: 101, webSocket: clientWS });
  },
};

function parseAllowlist(raw: string): Set<string> {
  const out = new Set<string>();
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (trimmed) out.add(trimmed);
  }
  return out;
}

function parseHostPort(
  dest: string
): { host: string; port: number } | null {
  const idx = dest.lastIndexOf(":");
  if (idx <= 0 || idx === dest.length - 1) return null;
  const host = dest.slice(0, idx);
  const port = parseInt(dest.slice(idx + 1), 10);
  if (!Number.isFinite(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

function pipeBytes(ws: WebSocket, socket: Socket): void {
  const writer = socket.writable.getWriter();

  ws.addEventListener("message", async (event) => {
    const data = event.data;
    try {
      if (data instanceof ArrayBuffer) {
        await writer.write(new Uint8Array(data));
      } else if (typeof data === "string") {
        await writer.write(new TextEncoder().encode(data));
      }
    } catch {
      try { ws.close(1011, "ws->tcp write failed"); } catch {}
      try { await socket.close(); } catch {}
    }
  });

  ws.addEventListener("close", async () => {
    try { await writer.close(); } catch {}
    try { await socket.close(); } catch {}
  });

  ws.addEventListener("error", async () => {
    try { await socket.close(); } catch {}
  });

  (async () => {
    const reader = socket.readable.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        try { ws.send(value); } catch { break; }
      }
      try { ws.close(1000, "tcp-closed"); } catch {}
    } catch {
      try { ws.close(1011, "tcp-error"); } catch {}
    }
  })();
}
