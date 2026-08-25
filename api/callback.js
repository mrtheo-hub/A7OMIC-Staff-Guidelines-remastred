// Vercel Edge Function: GET /api/callback?code=...
// Discord sends the user here after they approve the login.
export const config = { runtime: 'edge' };

export default async function handler(request) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  if (!code) return fail(url, 'missing_code');

  // CSRF check: the state Discord echoes back must match the nonce login.html set before redirecting
  const stateParam = url.searchParams.get('state');
  const stateCookie = readCookie(request.headers.get('cookie') || '', 'oauth_state');
  if (!stateParam || !stateCookie || stateParam !== stateCookie) {
    return fail(url, 'state_mismatch');
  }

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
  if (!memberRes.ok) return fail(url, 'not_member');
  const member = await memberRes.json();
  const roles = member.roles || [];

  // 3. only staff-role holders get through
  if (!roles.includes(DISCORD_STAFF_ROLE_ID)) return fail(url, 'not_staff');

  // 4. issue a signed 24h session cookie and send them to the real site
  const payload = { sub: member.user?.id, exp: Date.now() + 1000 * 60 * 60 * 24 };
  const session = await sign(payload, SESSION_SECRET);

  const res = Response.redirect(new URL('/', url), 302);
  res.headers.append(
    'Set-Cookie',
    `staff_session=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
  );
  res.headers.append('Set-Cookie', 'oauth_state=; Path=/; Max-Age=0; SameSite=Lax; Secure');
  return res;
}

function readCookie(header, name) {
  const match = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function fail(url, reason) {
  return new Response(null, {
    status: 302,
    headers: {
      // Backtick mengapit /login?error=${reason}
      'Location': new URL(`/login?error=${reason}`, url).toString()
    }
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
