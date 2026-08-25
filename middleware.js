// Runs on every request to "/" before the static file is served.
// No valid session cookie -> bounce to the login page instead of serving the guidelines.
export const config = {
  matcher: ['/'],
};

export default async function middleware(request) {
  const cookieHeader = request.headers.get('cookie') || '';
  const token = readCookie(cookieHeader, 'staff_session');

  if (token && (await verifySession(token, process.env.SESSION_SECRET))) {
    return; // valid session -> let the static index.html through
  }

  return Response.redirect(new URL('/login', request.url), 302);
}

function readCookie(header, name) {
  const match = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

// --- shared HMAC session format: base64url(payload).base64url(signature) ---
async function verifySession(token, secret) {
  try {
    const [payloadB64, sigB64] = token.split('.');
    if (!payloadB64 || !sigB64 || !secret) return false;

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
    if (!valid) return false;

    const payload = JSON.parse(atob(base64UrlToStd(payloadB64)));
    return typeof payload.exp === 'number' && Date.now() < payload.exp;
  } catch {
    return false;
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
