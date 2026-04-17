import { jwtVerify, createRemoteJWKSet } from "jose";

let cachedJWKS: ReturnType<typeof createRemoteJWKSet> | null = null;
let cachedUrl: string | null = null;

export async function verifyJwt(
  token: string,
  jwksUrl: string,
  issuer?: string,
  audience?: string
): Promise<Record<string, unknown> | null> {
  if (!cachedJWKS || cachedUrl !== jwksUrl) {
    cachedJWKS = createRemoteJWKSet(new URL(jwksUrl));
    cachedUrl = jwksUrl;
  }
  try {
    const { payload } = await jwtVerify(token, cachedJWKS, {
      issuer: issuer || undefined,
      audience: audience || undefined,
    });
    return payload;
  } catch {
    return null;
  }
}
