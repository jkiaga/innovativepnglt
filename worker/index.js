// Innovative PNG Ltd – tiny Cloudflare Worker.
//
//   GET  /api/content   public   the published site content (from KV)
//   PUT  /api/content   admin    publish new content (keeps the previous copy)
//   GET  /api/auth      admin    check the credentials work (returns who you are)
//   POST /api/upload    admin    upload a photo to R2, returns its path
//   POST /api/login     public   username + password -> session token
//   POST /api/logout    user     end the session
//   GET  /api/me        user     who am I
//   POST /api/me/password user   change my own password
//   GET/POST /api/users           owner   list / create users
//   PATCH/DELETE /api/users/<name> owner  change role, name, active, password / delete
//   GET  /img/*         public   photos from R2
//   anything else       static files (HTML, CSS, JS, fonts, images/) – handled by Cloudflare
//
// A request is "admin" when it carries  Authorization: Bearer <x>  where x is either
//   - the ADMIN_TOKEN secret (always an owner; the first-setup / emergency login), or
//   - a session token from /api/login for an active user (role: owner or editor).
// Users live in KV as  user:<username>; sessions as  session:<sha256(token)> (12 h).
// Bindings (see wrangler.toml): CONTENT (KV), PHOTOS (R2), ASSETS (static files).
// Secret: ADMIN_TOKEN  (wrangler secret put ADMIN_TOKEN)

const MAX_CONTENT_BYTES = 2 * 1024 * 1024;
const MAX_PHOTO_BYTES = 3 * 1024 * 1024;
const PHOTO_TYPES = { 'image/webp': 'webp', 'image/jpeg': 'jpg', 'image/png': 'png' };

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extra },
  });
}

// Compare two strings without leaking where they differ.
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

const ROLES = ['owner', 'editor'];
const PBKDF2_ITER = 100000;             // Workers' maximum
const SESSION_TTL = 12 * 60 * 60;       // seconds
const MAX_FAILS = 5, FAIL_TTL = 15 * 60;
const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;
const MIN_PASSWORD = 10;

const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
const toB64Url = (buf) => toB64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sha256Hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? fromB64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return { salt: toB64(salt), hash: toB64(bits) };
}

async function checkPassword(user, password) {
  const { hash } = await hashPassword(password, user.salt);
  return safeEqual(hash, user.hash);
}

async function getUser(env, username) { return env.CONTENT.get('user:' + username, 'json'); }
async function putUser(env, user) { await env.CONTENT.put('user:' + user.username, JSON.stringify(user)); }
async function listUsers(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.CONTENT.list({ prefix: 'user:', cursor });
    for (const k of page.keys) { const u = await env.CONTENT.get(k.name, 'json'); if (u) out.push(u); }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}
const publicUser = (u) => ({
  username: u.username, name: u.name, role: u.role, active: !!u.active,
  createdAt: u.createdAt, lastLogin: u.lastLogin || null,
});

async function createSession(env, user) {
  const token = toB64Url(crypto.getRandomValues(new Uint8Array(32)));
  await env.CONTENT.put(
    'session:' + (await sha256Hex(token)),
    JSON.stringify({ u: user.username, v: user.tokenVersion || 0 }),
    { expirationTtl: SESSION_TTL }
  );
  return token;
}

function bearer(request) {
  const m = (request.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : '';
}

// Who is making this request? null = nobody we trust.
async function getPrincipal(request, env) {
  const tok = bearer(request);
  if (!tok) return null;
  if (env.ADMIN_TOKEN && env.ADMIN_TOKEN.length >= 12 && (await safeEqual(tok, env.ADMIN_TOKEN))) {
    return { username: 'admin-token', name: 'Admin token', role: 'owner', viaToken: true };
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(tok)) return null;
  const sess = await env.CONTENT.get('session:' + (await sha256Hex(tok)), 'json');
  if (!sess) return null;
  const u = await getUser(env, sess.u);
  // Disabled, deleted, or password changed since this session began -> session is dead.
  if (!u || !u.active || (u.tokenVersion || 0) !== sess.v) return null;
  return { username: u.username, name: u.name, role: u.role, viaToken: false };
}
const canEdit = (p) => !!p && (p.role === 'owner' || p.role === 'editor');
const isOwner = (p) => !!p && p.role === 'owner';

function looksLikeContent(c) {
  return c && typeof c === 'object' && !Array.isArray(c) &&
    c.site && typeof c.site === 'object' &&
    Array.isArray(c.products) && Array.isArray(c.categories);
}

async function handleContent(request, env) {
  if (request.method === 'GET' || request.method === 'HEAD') {
    const text = await env.CONTENT.get('content');
    if (!text) return json({ error: 'No published content yet' }, 404, { 'Cache-Control': 'no-store' });
    return new Response(request.method === 'HEAD' ? null : text, {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        // Short cache: edits show up within about a minute, and most visitors are served from the edge.
        'Cache-Control': 'public, max-age=15, stale-while-revalidate=60',
      },
    });
  }

  if (request.method === 'PUT') {
    if (!canEdit(await getPrincipal(request, env))) return json({ error: 'Not allowed' }, 401);
    const text = await request.text();
    if (text.length > MAX_CONTENT_BYTES) return json({ error: 'Content is too large (max 2 MB).' }, 413);
    let parsed;
    try { parsed = JSON.parse(text); } catch (e) { return json({ error: 'That is not valid JSON.' }, 400); }
    if (!looksLikeContent(parsed)) return json({ error: 'That does not look like site content.' }, 400);
    const previous = await env.CONTENT.get('content');
    if (previous) await env.CONTENT.put('content:previous', previous);
    await env.CONTENT.put('content', JSON.stringify(parsed));
    return json({ ok: true, savedAt: new Date().toISOString() });
  }

  return json({ error: 'Method not allowed' }, 405, { Allow: 'GET, HEAD, PUT' });
}

async function handleAuth(request, env) {
  const p = await getPrincipal(request, env);
  return canEdit(p) ? json({ ok: true, user: p }) : json({ error: 'Not allowed' }, 401);
}

// ---------- accounts ----------
async function readJson(request) {
  try { const b = await request.json(); return b && typeof b === 'object' ? b : {}; } catch (e) { return {}; }
}
const cleanName = (v) => String(v || '').trim().slice(0, 60);

async function handleLogin(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  const body = await readJson(request);
  const username = String(body.username || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!USERNAME_RE.test(username) || !password) return json({ error: 'Wrong username or password.' }, 401);

  const fkey = 'fail:' + username;
  const fails = parseInt((await env.CONTENT.get(fkey)) || '0', 10);
  if (fails >= MAX_FAILS) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);

  const user = await getUser(env, username);
  // Always do the hashing work so unknown users cannot be told apart by timing.
  const ok = user ? await checkPassword(user, password) : (await hashPassword(password), false);
  if (!user || !ok || !user.active) {
    await env.CONTENT.put(fkey, String(fails + 1), { expirationTtl: FAIL_TTL });
    return json({ error: 'Wrong username or password.' }, 401);
  }
  await env.CONTENT.delete(fkey);
  user.lastLogin = new Date().toISOString();
  await putUser(env, user);
  const token = await createSession(env, user);
  return json({ ok: true, token, user: { username: user.username, name: user.name, role: user.role }, expiresIn: SESSION_TTL });
}

async function handleLogout(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  const tok = bearer(request);
  if (tok) await env.CONTENT.delete('session:' + (await sha256Hex(tok)));
  return json({ ok: true });
}

async function handleMe(request, env, sub) {
  const p = await getPrincipal(request, env);
  if (!p) return json({ error: 'Not allowed' }, 401);
  if (!sub) return request.method === 'GET' ? json({ ok: true, user: p }) : json({ error: 'Method not allowed' }, 405);
  if (sub === 'password' && request.method === 'POST') {
    if (p.viaToken) return json({ error: 'The admin token has no password. Create a user account instead.' }, 400);
    const body = await readJson(request);
    const next = String(body.next || '');
    if (next.length < MIN_PASSWORD) return json({ error: 'New password must be at least ' + MIN_PASSWORD + ' characters.' }, 400);
    const u = await getUser(env, p.username);
    if (!u || !(await checkPassword(u, String(body.current || '')))) return json({ error: 'Current password is wrong.' }, 403);
    Object.assign(u, await hashPassword(next));
    u.tokenVersion = (u.tokenVersion || 0) + 1;   // signs out every other session
    await putUser(env, u);
    return json({ ok: true, token: await createSession(env, u) });
  }
  return json({ error: 'Not found' }, 404);
}

function activeOwners(users) { return users.filter((u) => u.active && u.role === 'owner'); }

async function handleUsers(request, env, name) {
  const p = await getPrincipal(request, env);
  if (!isOwner(p)) return json({ error: 'Only owners can manage users.' }, 403);

  if (!name) {
    if (request.method === 'GET') return json({ users: (await listUsers(env)).map(publicUser).sort((a, b) => a.username.localeCompare(b.username)) });
    if (request.method === 'POST') {
      const b = await readJson(request);
      const username = String(b.username || '').trim().toLowerCase();
      const role = String(b.role || 'editor');
      const password = String(b.password || '');
      if (!USERNAME_RE.test(username)) return json({ error: 'Username: 3–32 characters, a–z, 0–9, dot, dash or underscore.' }, 400);
      if (!ROLES.includes(role)) return json({ error: 'Role must be owner or editor.' }, 400);
      if (password.length < MIN_PASSWORD) return json({ error: 'Password must be at least ' + MIN_PASSWORD + ' characters.' }, 400);
      if (await getUser(env, username)) return json({ error: 'That username is already taken.' }, 409);
      const user = {
        username, name: cleanName(b.name) || username, role, active: true,
        ...(await hashPassword(password)), tokenVersion: 0,
        createdAt: new Date().toISOString(), createdBy: p.username,
      };
      await putUser(env, user);
      return json({ ok: true, user: publicUser(user) }, 201);
    }
    return json({ error: 'Method not allowed' }, 405, { Allow: 'GET, POST' });
  }

  const username = decodeURIComponent(name).toLowerCase();
  const user = await getUser(env, username);
  if (!user) return json({ error: 'No such user.' }, 404);
  const all = await listUsers(env);
  const wouldLoseLastOwner = user.active && user.role === 'owner' && activeOwners(all).length <= 1;

  if (request.method === 'DELETE') {
    if (wouldLoseLastOwner) return json({ error: 'Keep at least one active owner.' }, 409);
    await env.CONTENT.delete('user:' + username);
    return json({ ok: true });
  }
  if (request.method === 'PATCH') {
    const b = await readJson(request);
    if ('role' in b) {
      if (!ROLES.includes(b.role)) return json({ error: 'Role must be owner or editor.' }, 400);
      if (b.role !== 'owner' && wouldLoseLastOwner) return json({ error: 'Keep at least one active owner.' }, 409);
      user.role = b.role;
    }
    if ('active' in b) {
      if (!b.active && wouldLoseLastOwner) return json({ error: 'Keep at least one active owner.' }, 409);
      user.active = !!b.active;
    }
    if ('name' in b) user.name = cleanName(b.name) || user.username;
    if ('password' in b && b.password !== '') {
      if (String(b.password).length < MIN_PASSWORD) return json({ error: 'Password must be at least ' + MIN_PASSWORD + ' characters.' }, 400);
      Object.assign(user, await hashPassword(String(b.password)));
    }
    // Any security-relevant change signs that user out everywhere.
    if ('role' in b || 'active' in b || ('password' in b && b.password !== '')) user.tokenVersion = (user.tokenVersion || 0) + 1;
    await putUser(env, user);
    return json({ ok: true, user: publicUser(user) });
  }
  return json({ error: 'Method not allowed' }, 405, { Allow: 'PATCH, DELETE' });
}

async function handleUpload(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  if (!canEdit(await getPrincipal(request, env))) return json({ error: 'Not allowed' }, 401);
  const type = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  const ext = PHOTO_TYPES[type];
  if (!ext) return json({ error: 'Only WebP, JPEG or PNG photos.' }, 415);
  const body = await request.arrayBuffer();
  if (!body.byteLength) return json({ error: 'Empty file.' }, 400);
  if (body.byteLength > MAX_PHOTO_BYTES) return json({ error: 'Photo is too large (max 3 MB).' }, 413);
  const id = crypto.randomUUID().slice(0, 8);
  const key = 'uploads/' + Date.now().toString(36) + '-' + id + '.' + ext;
  await env.PHOTOS.put(key, body, { httpMetadata: { contentType: type } });
  // The site stores this relative path in the content.
  return json({ ok: true, path: 'img/' + key });
}

async function handlePhoto(request, env, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'Method not allowed' }, 405);
  const key = decodeURIComponent(url.pathname.replace(/^\/img\//, ''));
  if (!key || key.includes('..')) return json({ error: 'Not found' }, 404);
  const obj = await env.PHOTOS.get(key);
  if (!obj) return json({ error: 'Not found' }, 404);
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('ETag', obj.httpEtag);
  // Uploaded file names are unique and never reused, so they can be cached for a long time.
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(request.method === 'HEAD' ? null : obj.body, { headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/api/content') return await handleContent(request, env);
      if (url.pathname === '/api/auth') return await handleAuth(request, env);
      if (url.pathname === '/api/upload') return await handleUpload(request, env);
      if (url.pathname === '/api/login') return await handleLogin(request, env);
      if (url.pathname === '/api/logout') return await handleLogout(request, env);
      if (url.pathname === '/api/me') return await handleMe(request, env, '');
      if (url.pathname === '/api/me/password') return await handleMe(request, env, 'password');
      if (url.pathname === '/api/users') return await handleUsers(request, env, '');
      if (url.pathname.startsWith('/api/users/')) return await handleUsers(request, env, url.pathname.slice('/api/users/'.length));
      if (url.pathname.startsWith('/img/')) return await handlePhoto(request, env, url);
      if (url.pathname.startsWith('/api/')) return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error' }, 500);
    }
    return env.ASSETS.fetch(request);
  },
};
