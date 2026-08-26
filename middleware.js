// Runs on every request to "/" or "/index.html" before the static file is served.
// No valid session cookie -> bounce to the login page instead of serving the guidelines.
// Both paths are matched deliberately: gating only "/" leaves the same file reachable
// at "/index.html" as an unguarded bypass, since that's the same static asset.
export const config = {
  matcher: ['/', '/index.html'],
};

export default async function middleware(request) {
  const cookieHeader = request.headers.get('cookie') || '';
  const token = readCookie(cookieHeader, 'staff_session');

  if (token) {
    const result = await verifySession(token, process.env.SESSION_SECRET);
    if (result === 'valid') return; // let the static index.html through
    if (result === 'invalid') {
      // signature didn't match at all -> a forged or tampered cookie, not just an expired one
      await sendAlert('tampered_session_cookie', 'A staff_session cookie failed signature verification.', request);
    }
    // 'expired' -> normal, no alert, everyone's session runs out eventually
  }

  return Response.redirect(new URL('/login', request.url), 302);
}

function readCookie(header, name) {
  const match = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

// --- shared HMAC session format: base64url(payload).base64url(signature) ---
// returns 'valid' | 'expired' | 'invalid' instead of a plain boolean so callers
// can tell "signature is wrong" (worth an alert) apart from "just ran out" (not).
async function verifySession(token, secret) {
  try {
    const [payloadB64, sigB64] = token.split('.');
    if (!payloadB64 || !sigB64 || !secret) return 'invalid';

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlToBytes(sigB64),
      new TextEncoder().encode(payloadB64)
    );
    if (!valid) return 'invalid';

    const payload = JSON.parse(atob(base64UrlToStd(payloadB64)));
    if (typeof payload.exp !== 'number') return 'invalid';
    return Date.now() < payload.exp ? 'valid' : 'expired';
  } catch {
    return 'invalid';
  }
}

function base64UrlToStd(b64url) {
  return b64url.replace(/-/g, '+').replace(/_/g, '/');
}
function base64UrlToBytes(b64url) {
  const bin = atob(base64UrlToStd(b64url));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// --- security alerting: posts to a Discord webhook, never throws, no-ops if unset ---
async function sendAlert(event, detail, request) {
  const webhook = process.env.ALERT_WEBHOOK_URL;
  if (!webhook) return;
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
  const ua = (request.headers.get('user-agent') || 'unknown').slice(0, 200);
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `Security alert: ${event}`,
          description: detail,
          color: 0xef4444,
          fields: [
            { name: 'IP', value: ip, inline: true },
            { name: 'Time', value: new Date().toISOString(), inline: true },
            { name: 'User-Agent', value: ua, inline: false },
          ],
        }],
      }),
    });
  } catch {
    // an alert failing to send must never block or break the actual request
  }
}
