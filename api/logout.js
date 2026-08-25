export const config = { runtime: 'edge' };

export default async function handler(request) {
  const headers = new Headers();
  headers.set('Location', new URL('/login', request.url).toString());
  headers.append(
    'Set-Cookie',
    'staff_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
  );

  return new Response(null, {
    status: 302,
    headers,
  });
}
