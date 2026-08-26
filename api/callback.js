// Vercel Edge Function: GET /api/callback?code=...
// Discord sends the user here after they approve the login.
export const config = { runtime: 'edge' };

export default async function handler(request) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  if (!code) return fail(url, 'missing_code');

  const cookieHeader = request.headers.get('cookie') || '';

  // CSRF check: the state Discord echoes back must match the nonce login.html set before redirecting
  const stateParam = url.searchParams.get('state');
  const stateCookie = readCookie(cookieHeader, 'oauth_state');
  if (!stateParam || !stateCookie || stateParam !== stateCookie) {
    await sendAlert('oauth_state_mismatch', 'A callback request arrived with a missing or non-matching OAuth state, possible forged login link.', request);
    return fail(url, 'state_mismatch');
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
  if (!tokenRes.ok) return fail(url, 'token_exchange');
  const { access_token } = await tokenRes.json();

  // 2. ask Discord "is this person a member of our guild, and what are their roles"
  const memberRes = await fetch(
    `https://discord.com/api/users/@me/guilds/${DISCORD_GUILD_ID}/member`,
    { headers: { Authorization: `Bearer ${access_token}` } }
  );
  if (!memberRes.ok) {
    await sendAlert('login_not_a_member', 'A Discord account completed login but is not a member of the A7OMIC server.', request);
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
