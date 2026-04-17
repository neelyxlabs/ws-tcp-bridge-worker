/**
 * HMAC helpers for the bridge's signed URL scheme.
 *
 * URL shape: `/?dest=<host:port>&exp=<unix-seconds>&sig=<hex>`
 *
 * `sig = HMAC-SHA256(secret, "<dest>|<exp>")` where `|` is a literal pipe
 * (chosen because it's not a valid character in hostnames or unsigned
 * integers, so the components cannot be confused even without length
 * prefixing).
 *
 * The signature binds to BOTH dest and exp — a leaked URL is scoped to a
 * single destination for the remainder of its TTL. Recommended TTL for
 * consumers is 5 minutes; shorter is fine. Longer invites replay.
 */

/**
 * Verify a signed URL. Returns true if:
 *   - sig matches HMAC-SHA256(secret, dest + "|" + exp)
 *   - exp is in the future (wall clock time)
 *
 * NOTE: timingSafeEqual-style constant-time compare is used by
 * `crypto.subtle.verify` internally, so there's no leak to worry about.
 */
export async function verifySignedUrl(
  secret: string,
  dest: string,
  exp: number,
  sigHex: string
): Promise<boolean> {
  if (!secret || !dest || !sigHex || !Number.isFinite(exp)) return false;
  if (Date.now() > exp * 1000) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const providedSig = hexToBytes(sigHex);
  if (!providedSig) return false;

  const data = new TextEncoder().encode(`${dest}|${exp}`);
  return crypto.subtle.verify("HMAC", key, providedSig, data);
}

/**
 * Sign a URL client-side. Usually clients implement their own signing in
 * their own codebase — this helper is exported for testing and for ad-hoc
 * tools.
 */
export async function signUrl(
  secret: string,
  dest: string,
  ttlSeconds = 300
): Promise<{ dest: string; exp: number; sig: string }> {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = new TextEncoder().encode(`${dest}|${exp}`);
  const sigBuf = await crypto.subtle.sign("HMAC", key, data);
  return { dest, exp, sig: bytesToHex(new Uint8Array(sigBuf)) };
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length === 0 || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}
