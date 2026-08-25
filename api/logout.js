export const config = { runtime: 'edge' };

export default async function handler(request) {
  const res = Response.redirect(new URL('/login', request.url), 302);
  res.headers.append('Set-Cookie', 'staff_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  return res;
}
