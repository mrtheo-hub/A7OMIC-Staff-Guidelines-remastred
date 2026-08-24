// GET /api/roster?role=DISCORD_ROLE_ID
// Returns [{ name, avatar }] for every non-bot member holding that role.
// No presence/online-status data — membership only.
export const config = { runtime: 'edge' };

export default async function handler(request) {
  const url = new URL(request.url);
  const roleId = url.searchParams.get('role');
  if (!roleId) return json({ error: 'missing role param' }, 400);

  // reuse the same session check as the site itself — this endpoint is not public
  const cookie = request.headers.get('cookie') || '';
  const token = readCookie(cookie, 'staff_session');
  if (!token || !(await verifySession(token, process.env.SESSION_SECRET))) {
    return json({ error: 'unauthorized' }, 401);
  }

  const { DISCORD_GUILD_ID, DISCORD_BOT_TOKEN } = process.env;

  const membersRes = await fetch(
    `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members?limit=1000`,
    { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
  );
  if (!membersRes.ok) {
    return json({ error: 'discord_fetch_failed', status: membersRes.status }, 502);
  }
  const members = await membersRes.json();

  const matches = members
    .filter((m) => !m.user?.bot && Array.isArray(m.roles) && m.roles.includes(roleId))
    .map((m) => ({
      name: m.nick || m.user?.global_name || m.user?.username || 'Unknown',
      avatar: avatarUrl(m.user),
    }));

  return json(matches, 200);
}

function avatarUrl(user) {
  if (!user) return '';
  if (user.avatar) {
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64`;
  }
  // no custom avatar -> Discord's default avatar set
  const idx = Number((BigInt(user.id) >> 22n) % 6n);
  return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function readCookie(header, name) {
  const match = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

// --- same HMAC session format used by middleware.js / callback.js ---
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
