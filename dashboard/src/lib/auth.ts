import { cookies } from "next/headers";
import crypto from "crypto";

const AUTH_COOKIE = "clif_session";
const TOKEN_MAX_AGE = 60 * 60 * 24; // 24 hours in seconds

// Credentials from environment or defaults
function getCredentials() {
  return {
    username: process.env.CLIF_AUTH_USER || "admin",
    password: process.env.CLIF_AUTH_PASS || "clif2026",
  };
}

function getSecret(): string {
  return process.env.CLIF_AUTH_SECRET || "clif-nexus-default-secret-change-me";
}

/** Create a signed session token */
export function createSessionToken(): string {
  const payload = JSON.stringify({
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + TOKEN_MAX_AGE,
  });
  const b64 = Buffer.from(payload).toString("base64url");
  const sig = crypto
    .createHmac("sha256", getSecret())
    .update(b64)
    .digest("base64url");
  return `${b64}.${sig}`;
}

/** Verify a session token is valid and not expired */
export function verifySessionToken(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [b64, sig] = parts;

  // Check signature
  const expectedSig = crypto
    .createHmac("sha256", getSecret())
    .update(b64)
    .digest("base64url");
  if (sig !== expectedSig) return false;

  // Check expiry
  try {
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;
  } catch {
    return false;
  }
  return true;
}

/** Validate login credentials */
export function validateCredentials(
  username: string,
  password: string,
): boolean {
  const creds = getCredentials();
  // Constant-time comparison to prevent timing attacks
  // Pad to equal lengths before comparing
  const maxUserLen = Math.max(username.length, creds.username.length);
  const maxPassLen = Math.max(password.length, creds.password.length);
  const userMatch = crypto.timingSafeEqual(
    Buffer.from(username.padEnd(maxUserLen)),
    Buffer.from(creds.username.padEnd(maxUserLen)),
  ) && username.length === creds.username.length;
  const passMatch = crypto.timingSafeEqual(
    Buffer.from(password.padEnd(maxPassLen)),
    Buffer.from(creds.password.padEnd(maxPassLen)),
  ) && password.length === creds.password.length;
  return userMatch && passMatch;
}

/** Check if current request is authenticated (server component) */
export async function isAuthenticated(): Promise<boolean> {
  const cookieStore = await cookies();
  const token = cookieStore.get(AUTH_COOKIE)?.value;
  if (!token) return false;
  return verifySessionToken(token);
}

export { AUTH_COOKIE, TOKEN_MAX_AGE };
