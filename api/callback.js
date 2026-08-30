// Vercel Edge Function: GET /api/callback?code=...
// Discord sends the user here after they approve the login.
export const config = { runtime: 'edge' };

const SCANNER_UA = /sqlmap|nikto|nmap|masscan|nessus|acunetix|w3af|dirbuster|gobuster|wpscan|burp|zaproxy/i;

export default async function handler(request) {
  const url = new URL(request.url);

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    await sendAlert('unexpected_method', `A ${request.method} request hit /api/callback instead of GET.`, request, 'medium');
  }
  flagScannerUA(request);

  const code = url.searchParams.get('code');
  if (!code) {
    await sendAlert('callback_missing_code', 'Someone hit /api/callback directly with no code param, likely manual probing rather than a real Discord redirect.', request, 'low');
    return fail(url, 'missing_code');
  }

  const cookieHeader = request.headers.get('cookie') || '';

  // CSRF check: the state Discord echoes back must match the nonce login.html set before redirecting
  const stateParam = url.searchParams.get('state');
  const stateCookie = readCookie(cookieHeader, 'oauth_state');
  if (!stateParam || !stateCookie || stateParam !== stateCookie) {
    await sendAlert('oauth_state_mismatch', 'A callback request arrived with a missing or non-matching OAuth state, possible forged login link.', request, 'high');
    return fail(url, 'state_mismatch');
  }

  // Turnstile: the widget alone proves nothing, only this server-side check does.
  // A missing/failing token here despite the button being gated on having one client-side
  // means someone skipped the widget entirely, worth an alert, not just a quiet redirect.
  const turnstileToken = readCookie(cookieHeader, 'turnstile_token');
  if (!turnstileToken) {
    await sendAlert('turnstile_missing', 'Callback reached with no Turnstile token at all, the widget was likely bypassed.', request, 'high');
    return fail(url, 'turnstile_failed');
  }
  const clientIp = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || '';
  const tsRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: process.env.TURNSTILE_SECRET_KEY,
      response: turnstileToken,
      remoteip: clientIp,
    }),
  });
  const tsResult = await tsRes.json();
  if (!tsResult.success) {
    await sendAlert('turnstile_failed', `Turnstile siteverify rejected the token: ${(tsResult['error-codes'] || []).join(', ') || 'unknown reason'}.`, request, 'high');
    return fail(url, 'turnstile_failed');
  }

  const rememberMe = readCookie(cookieHeader, 'remember_me') === '1';

  const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DISCORD_REDIRECT_URI,
    DISCORD_GUILD_ID,
    DISCORD_STAFF_ROLE_ID,
    SESSION_SECRET,
  } = process.env;

  // 1. exchange the one-time code for an access token
  const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: DISCORD_REDIRECT_URI,
    }),
  });
  if (!tokenRes.ok) {
    // a valid-looking code that Discord rejects is consistent with a reused,
    // expired, or fabricated code, worth knowing about even though it's rare
    await sendAlert('token_exchange_failed', `Discord rejected the authorization code (HTTP ${tokenRes.status}). Possible replayed or forged code.`, request, 'high');
    return fail(url, 'token_exchange');
  }
  const { access_token } = await tokenRes.json();

  // 2. ask Discord "is this person a member of our guild, and what are their roles"
  const memberRes = await fetch(
    `https://discord.com/api/users/@me/guilds/${DISCORD_GUILD_ID}/member`,
    { headers: { Authorization: `Bearer ${access_token}` } }
  );
  if (!memberRes.ok) {
    await sendAlert('login_not_a_member', 'A Discord account completed login but is not a member of the A7OMIC server.', request, 'high');
    return fail(url, 'not_member');
  }
  const member = await memberRes.json();
  const roles = member.roles || [];

  // 3. only staff-role holders get through (not alerted: a curious member with no staff
  // role trying the login button is expected traffic, not a security signal on its own)
  if (!roles.includes(DISCORD_STAFF_ROLE_ID)) return fail(url, 'not_staff');

  // 4. issue a signed session cookie: 24h normally, 30d if "remember me" was checked
  const maxAgeSeconds = rememberMe ? 60 * 60 * 24 * 30 : 60 * 60 * 24;
  const payload = { sub: member.user?.id, exp: Date.now() + maxAgeSeconds * 1000 };
  const session = await sign(payload, SESSION_SECRET);

  const headers = new Headers();
  headers.set('Location', new URL('/', url).toString());
  headers.append(
    'Set-Cookie',
    `staff_session=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`
  );
  headers.append('Set-Cookie', 'oauth_state=; Path=/; Max-Age=0; SameSite=Lax; Secure');
  headers.append('Set-Cookie', 'remember_me=; Path=/; Max-Age=0; SameSite=Lax; Secure');
  headers.append('Set-Cookie', 'turnstile_token=; Path=/; Max-Age=0; SameSite=Lax; Secure');

  return new Response(null, {
    status: 302,
    headers,
  });
}

function readCookie(header, name) {
  const match = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function fail(url, reason) {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': new URL(`/login?error=${reason}`, url).toString(),
    },
  });
}

function flagScannerUA(request) {
  const ua = request.headers.get('user-agent') || '';
  if (SCANNER_UA.test(ua)) {
    sendAlert('scanner_useragent_detected', `Request User-Agent matched a known scanning-tool signature: "${ua.slice(0, 120)}".`, request, 'medium');
  }
}

async function sign(payload, secret) {
  const payloadB64 = toBase64Url(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${toBase64UrlFromBytes(new Uint8Array(sigBuf))}`;
}

function toBase64Url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toBase64UrlFromBytes(bytes) {
  return toBase64Url(String.fromCharCode(...bytes));
}

// --- security alerting: posts to a Discord webhook, never throws, no-ops if unset ---
async function sendAlert(event, detail, request, severity) {
  const webhook = process.env.ALERT_WEBHOOK_URL;
  if (!webhook) return;
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
  const ua = (request.headers.get('user-agent') || 'unknown').slice(0, 200);
  const color = severity === 'high' ? 0xef4444 : severity === 'medium' ? 0xf59e0b : 0x94a3b8;
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `Security alert (${severity || 'info'}): ${event}`,
          description: detail,
          color,
          fields: [
            { name: 'IP', value: ip, inline: true },
            { name: 'Method', value: request.method, inline: true },
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
