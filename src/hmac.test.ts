import { describe, expect, it } from "vitest";
import { signUrl, verifySignedUrl } from "./hmac";

const SECRET = "test-secret-not-for-production";

describe("signUrl + verifySignedUrl", () => {
  it("round-trips: fresh signed URL verifies true", async () => {
    const { dest, exp, sig } = await signUrl(SECRET, "sftp.example.com:22", 60);
    const ok = await verifySignedUrl(SECRET, dest, exp, sig);
    expect(ok).toBe(true);
  });

  it("rejects wrong secret", async () => {
    const { dest, exp, sig } = await signUrl(SECRET, "sftp.example.com:22", 60);
    const ok = await verifySignedUrl("different-secret", dest, exp, sig);
    expect(ok).toBe(false);
  });

  it("rejects wrong destination (signature binds to dest)", async () => {
    const { exp, sig } = await signUrl(SECRET, "sftp.example.com:22", 60);
    // Attempt to reuse the signature for a different dest.
    const ok = await verifySignedUrl(SECRET, "other.example.com:22", exp, sig);
    expect(ok).toBe(false);
  });

  it("rejects wrong exp (signature binds to exp)", async () => {
    const { dest, exp, sig } = await signUrl(SECRET, "sftp.example.com:22", 60);
    const ok = await verifySignedUrl(SECRET, dest, exp + 1, sig);
    expect(ok).toBe(false);
  });

  it("rejects expired URL even with valid signature", async () => {
    const { dest, sig } = await signUrl(SECRET, "sftp.example.com:22", 60);
    // Construct an exp in the past with a matching signature for that exp.
    const pastExp = Math.floor(Date.now() / 1000) - 10;
    // Re-sign for past exp so the signature *matches* but the expiry check fails.
    const resigned = await signUrl(SECRET, "sftp.example.com:22", -10);
    const ok = await verifySignedUrl(SECRET, dest, pastExp, resigned.sig);
    expect(ok).toBe(false);
    // We also expect the above sig variable not to be used; silence unused-var.
    expect(sig.length).toBeGreaterThan(0);
  });

  it("rejects malformed hex signature", async () => {
    const { dest, exp } = await signUrl(SECRET, "sftp.example.com:22", 60);
    const ok = await verifySignedUrl(SECRET, dest, exp, "zzzzzz");
    expect(ok).toBe(false);
  });

  it("rejects empty signature", async () => {
    const { dest, exp } = await signUrl(SECRET, "sftp.example.com:22", 60);
    const ok = await verifySignedUrl(SECRET, dest, exp, "");
    expect(ok).toBe(false);
  });

  it("rejects missing destination", async () => {
    const { exp, sig } = await signUrl(SECRET, "sftp.example.com:22", 60);
    const ok = await verifySignedUrl(SECRET, "", exp, sig);
    expect(ok).toBe(false);
  });
});
