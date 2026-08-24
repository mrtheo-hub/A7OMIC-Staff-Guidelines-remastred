export const config = { runtime: 'edge' };

export default async function handler(request) {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': new URL('/login.html', request.url).toString(),
      'Set-Cookie': 'staff_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    }
  });
}
