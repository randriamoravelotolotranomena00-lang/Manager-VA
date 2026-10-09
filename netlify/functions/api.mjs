// CRM Manager VA — API en fonction Netlify (Functions v2) + Postgres (Netlify DB / Neon).
import crypto from 'node:crypto';
import { neon } from '@neondatabase/serverless';

// ---------- Erreurs ----------
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (m) => new HttpError(400, m);
const forbid = () => new HttpError(403, 'Accès refusé');
const notFound = () => new HttpError(404, 'Introuvable');

// ---------- Clés (dérivées de APP_KEY) ----------
let KEYS;
function keys() {
  if (KEYS) return KEYS;
  const k = process.env.APP_KEY;
  if (!k || k.length < 16) throw new HttpError(500, 'APP_KEY manquant : ajoute une phrase secrète longue (16 caractères min) dans les variables d\'environnement Netlify.');
  KEYS = {
    enc: crypto.createHash('sha256').update(k).digest(),                       // chiffrement des logins / 2FA
    session: crypto.createHmac('sha256', k).update('session-cookie').digest(), // signature des cookies de session
  };
  return KEYS;
}
function enc(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', keys().enc, iv);
  const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function dec(b64) {
  if (!b64) return '';
  try {
    const b = Buffer.from(b64, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', keys().enc, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
  } catch { return ''; }
}

// ---------- Mots de passe de connexion (scrypt) ----------
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const h = crypto.scryptSync(pw, salt, 64);
  const s = Buffer.from(hash, 'hex');
  return h.length === s.length && crypto.timingSafeEqual(h, s);
}

// ---------- TOTP (RFC 6238) ----------
function b32decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of s) bits += A.indexOf(ch).toString(2).padStart(5, '0');
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret) {
  const key = b32decode(secret);
  if (!key.length) return '';
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', key).update(ctr).digest();
  const o = h[h.length - 1] & 0xf;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}

// ---------- Base de données (Postgres) ----------
let _sql;
function getSql() {
  if (_sql) return _sql;
  const url = process.env.NETLIFY_DATABASE_URL || process.env.DATABASE_URL;
  if (!url) throw new HttpError(500, 'Base de données non configurée : lance « npx netlify db init » (voir README).');
  return (_sql = neon(url));
}
async function q(text, params = []) {
  const r = await getSql().query(text, params);
  return Array.isArray(r) ? r : r.rows;
}
const one = async (text, params) => (await q(text, params))[0];

const NOW_TXT = "to_char(timezone('utc', now()), 'YYYY-MM-DD HH24:MI:SS')";
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','manager','va')),
    password_hash TEXT NOT NULL,
    manager_id INTEGER,
    discord TEXT DEFAULT '',
    telegram TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    rate DOUBLE PRECISION,
    retired INTEGER NOT NULL DEFAULT 0,
    last_login TEXT,
    created_at TEXT NOT NULL DEFAULT ${NOW_TXT}
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username))`,
  `CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    va_id INTEGER NOT NULL REFERENCES users(id),
    platform TEXT NOT NULL DEFAULT 'instagram',
    url TEXT NOT NULL,
    handle TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'actif',
    login_user TEXT DEFAULT '',
    password_enc TEXT DEFAULT '',
    totp_enc TEXT DEFAULT '',
    no2fa INTEGER NOT NULL DEFAULT 0,
    followers INTEGER,
    added_by_va INTEGER NOT NULL DEFAULT 0,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ${NOW_TXT}
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS accounts_platform_handle ON accounts (platform, lower(handle))`,
  `CREATE INDEX IF NOT EXISTS accounts_va ON accounts (va_id)`,
  `CREATE TABLE IF NOT EXISTS penalties (
    id SERIAL PRIMARY KEY,
    va_id INTEGER NOT NULL REFERENCES users(id),
    amount DOUBLE PRECISION NOT NULL,
    reason TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ${NOW_TXT}
  )`,
  `CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, until_ms BIGINT NOT NULL DEFAULT 0)`,
  // settings en dernier : sa présence prouve que tout le schéma existe
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `INSERT INTO settings (key, value) VALUES ('rate_per_account', '1.5') ON CONFLICT (key) DO NOTHING`,
];

let ready = null;
function ensureReady() {
  if (!ready) {
    ready = (async () => {
      const t = await one("SELECT to_regclass('public.settings')::text AS t");
      if (!t || !t.t) for (const s of SCHEMA) await q(s);
      // Migration : la base existante n'accepte pas encore le rôle « admin »
      const checks = await q("SELECT conname, pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid='users'::regclass AND contype='c'");
      const roleChecks = checks.filter((c) => c.d.includes('role'));
      if (roleChecks.length && !roleChecks.some((c) => c.d.includes("'admin'"))) {
        for (const c of roleChecks) await q(`ALTER TABLE users DROP CONSTRAINT "${c.conname}"`);
        await q("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','manager','va'))");
      }
      // Migration : colonne « réseau » des comptes (base existante = tout Instagram)
      if (!(await one("SELECT 1 AS x FROM information_schema.columns WHERE table_name='accounts' AND column_name='platform'"))) {
        await q("ALTER TABLE accounts ADD COLUMN platform TEXT NOT NULL DEFAULT 'instagram'");
        await q('DROP INDEX IF EXISTS accounts_handle_lower');
        await q('CREATE UNIQUE INDEX IF NOT EXISTS accounts_platform_handle ON accounts (platform, lower(handle))');
      }
      // Il doit toujours exister un admin : le premier compte créé (MANAGER_USER) le devient
      if (!(await one("SELECT 1 AS x FROM users WHERE role='admin' LIMIT 1"))) {
        const wanted = (process.env.MANAGER_USER || '').trim();
        let target = wanted ? await one("SELECT id FROM users WHERE lower(username)=lower($1) AND role='manager'", [wanted]) : null;
        if (!target) target = await one("SELECT id FROM users WHERE role='manager' ORDER BY id LIMIT 1");
        if (target) {
          await q("UPDATE users SET role='admin' WHERE id=$1", [target.id]);
        } else {
          const pass = process.env.MANAGER_PASS;
          if (!pass || pass.length < 8) {
            throw new HttpError(500, 'Aucun compte admin : ajoute MANAGER_PASS (8 caractères min) dans les variables Netlify, puis redéploie.');
          }
          const user = (wanted || 'admin').trim();
          await q("INSERT INTO users (username, name, role, password_hash) VALUES ($1,$2,'admin',$3) ON CONFLICT DO NOTHING",
            [user, user, hashPw(pass)]);
          console.log('Compte admin créé :', user);
        }
      }
    })().catch((e) => { ready = null; throw e; });
  }
  return ready;
}

const STATUSES = ['actif', 'chauffe', 'shadowban', 'banni'];
const COUNTED_SQL = "('actif','chauffe','shadowban')"; // comptes qui comptent pour la paie
const getRate = async () => Number((await one("SELECT value FROM settings WHERE key='rate_per_account'")).value);

// ---------- Sessions (cookie signé, sans état serveur) ----------
const SESSION_S = 12 * 3600;
const pwFp = (hash) => crypto.createHash('sha256').update(String(hash)).digest('hex').slice(0, 16);
const sign = (payload, hash) => crypto.createHmac('sha256', keys().session).update(payload + '.' + pwFp(hash)).digest('base64url');
function makeToken(u) {
  const p = `${u.id}.${Math.floor(Date.now() / 1000) + SESSION_S}`;
  return `${p}.${sign(p, u.password_hash)}`;
}
function cookieStr(value, maxAge, secure) {
  return `sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` + (secure ? '; Secure' : '');
}
function parseCookies(req) {
  const out = {};
  for (const p of String(req.headers.get('cookie') || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch { /* ignoré */ } }
  }
  return out;
}
async function currentUser(req) {
  const t = parseCookies(req).sid;
  if (!t) return null;
  const [id, exp, sig] = t.split('.');
  if (!/^\d+$/.test(id || '') || !/^\d+$/.test(exp || '') || !sig || Number(exp) * 1000 < Date.now()) return null;
  const u = await one('SELECT * FROM users WHERE id=$1', [Number(id)]);
  if (!u || u.retired) return null;
  const good = Buffer.from(sign(`${id}.${exp}`, u.password_hash));
  const got = Buffer.from(sig);
  if (good.length !== got.length || !crypto.timingSafeEqual(good, got)) return null;
  // session glissante : on renouvelle le cookie s'il a plus de 10 minutes
  const refresh = Number(exp) - Math.floor(Date.now() / 1000) < SESSION_S - 600;
  return { user: u, refresh };
}

// ---------- Utilitaires métier ----------
const PLATFORMS = {
  instagram: { label: 'Instagram', site: 'https://www.instagram.com', hosts: ['instagram.com'] },
  tiktok:    { label: 'TikTok', site: 'https://www.tiktok.com', hosts: ['tiktok.com'], at: true },
  facebook:  { label: 'Facebook', site: 'https://www.facebook.com', hosts: ['facebook.com', 'fb.com'] },
  x:         { label: 'X (Twitter)', site: 'https://x.com', hosts: ['x.com', 'twitter.com'] },
  youtube:   { label: 'YouTube', site: 'https://www.youtube.com', hosts: ['youtube.com'], at: true, skip: ['channel', 'c', 'user'] },
  snapchat:  { label: 'Snapchat', site: 'https://www.snapchat.com', hosts: ['snapchat.com'], skip: ['add'], pre: 'add/' },
  threads:   { label: 'Threads', site: 'https://www.threads.com', hosts: ['threads.net', 'threads.com'], at: true },
  linkedin:  { label: 'LinkedIn', site: 'https://www.linkedin.com', hosts: ['linkedin.com'], skip: ['in', 'company'], pre: 'in/' },
  telegram:  { label: 'Telegram', site: 'https://t.me', hosts: ['t.me', 'telegram.me'] },
  reddit:    { label: 'Reddit', site: 'https://www.reddit.com', hosts: ['reddit.com'], skip: ['user', 'u'], pre: 'user/' },
  pinterest: { label: 'Pinterest', site: 'https://www.pinterest.com', hosts: ['pinterest.com'] },
  autre:     { label: 'Autre', hosts: [] },
};
// Lit un lien (ou un simple pseudo) et renvoie { url propre, handle, login par défaut }
function parseAccount(platform, input) {
  const P = PLATFORMS[platform];
  if (!P) throw bad('Réseau inconnu');
  let u = String(input || '').trim();
  if (!u) throw bad('Lien du compte requis');
  if (!/^https?:\/\//i.test(u)) {
    const name = u.replace(/^@/, '');
    if (!P.site || !/^[^\s/?#]{1,100}$/.test(name)) throw bad('Colle le lien complet du compte (https://…)');
    u = `${P.site}/${P.pre || ''}${P.at ? '@' : ''}${name}`;
  }
  let parsed;
  try { parsed = new URL(u); } catch { throw bad('Lien invalide'); }
  const host = parsed.hostname.toLowerCase().replace(/^(www|m|mobile|web)\./, '');
  if (P.hosts.length && !P.hosts.some((h) => host === h || host.endsWith('.' + h))) throw bad(`Ce lien n'est pas un lien ${P.label}`);
  const segs = parsed.pathname.split('/').filter(Boolean);
  if (platform === 'autre') {
    const path = segs.join('/');
    return { url: `${parsed.protocol}//${parsed.host}${path ? '/' + path : ''}`, handle: path ? `${host}/${segs[segs.length - 1]}` : host, login: '' };
  }
  if (platform === 'facebook' && segs[0] === 'profile.php') {
    const id = parsed.searchParams.get('id');
    if (!id || !/^\d+$/.test(id)) throw bad('Lien Facebook invalide');
    return { url: `${P.site}/profile.php?id=${id}`, handle: '@id' + id, login: '' };
  }
  let skipUsed = '';
  if (P.skip && segs[0] && P.skip.includes(segs[0].toLowerCase())) skipUsed = segs.shift().toLowerCase();
  const name = segs[0];
  if (!name) throw bad('Impossible de lire le pseudo dans le lien');
  const bare = name.replace(/^@/, '');
  if (!bare) throw bad('Impossible de lire le pseudo dans le lien');
  return { url: `${P.site}/${skipUsed ? skipUsed + '/' : ''}${name}`, handle: '@' + bare, login: bare };
}
const cleanTotp = (s) => String(s || '').replace(/\s+/g, '').toUpperCase();

// Semaine de paie : samedi → vendredi
function weekRange(offset = 0) {
  const now = new Date();
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 1) % 7) + offset * 7);
  const end = new Date(d); end.setUTCDate(end.getUTCDate() + 7);
  const iso = (x) => x.toISOString().slice(0, 10);
  const last = new Date(end); last.setUTCDate(last.getUTCDate() - 1);
  return { start: iso(d), end: iso(end), last: iso(last) };
}

// Paie de tous les VA actifs (ou d'un seul VA, même retiré) en UNE requête
async function payRows(week, onlyId) {
  const params = [week.start, week.end];
  let where = "u.role='va' AND u.retired=0";
  if (onlyId) { where = "u.role='va' AND u.id=$3"; params.push(Number(onlyId)); }
  const rows = await q(`SELECT u.id, u.name,
      COALESCE(u.rate, (SELECT value::float8 FROM settings WHERE key='rate_per_account')) AS rate,
      (SELECT COUNT(*) FROM accounts a WHERE a.va_id=u.id AND a.status IN ${COUNTED_SQL})::int AS counted,
      (SELECT COALESCE(SUM(p.amount),0) FROM penalties p WHERE p.va_id=u.id
         AND substr(p.created_at,1,10)>=$1 AND substr(p.created_at,1,10)<$2)::float8 AS penalties
    FROM users u WHERE ${where} ORDER BY lower(u.name)`, params);
  return rows.map((r) => {
    const gross = r.counted * Number(r.rate);
    return { va_id: r.id, name: r.name, rate: Number(r.rate), counted: r.counted, gross, penalties: r.penalties, net: Math.max(0, gross - r.penalties) };
  });
}
async function payFor(vaId, week) {
  const [r] = await payRows(week, vaId);
  const { va_id, name, ...pay } = r || { rate: await getRate(), counted: 0, gross: 0, penalties: 0, net: 0 };
  return pay;
}

const pubUser = (u) => ({
  id: u.id, username: u.username, name: u.name, role: u.role, manager_id: u.manager_id,
  discord: u.discord, telegram: u.telegram, phone: u.phone, rate: u.rate, retired: !!u.retired,
  last_login: u.last_login, created_at: u.created_at,
});
const pubAccount = (a) => ({
  id: a.id, va_id: a.va_id, va_name: a.va_name, platform: a.platform, url: a.url, handle: a.handle, status: a.status,
  login_user: a.login_user, has_password: !!a.password_enc, has_2fa: !!a.totp_enc, no2fa: !!a.no2fa,
  followers: a.followers, added_by_va: !!a.added_by_va, note: a.note, created_at: a.created_at,
});
async function accountForUser(user, id) {
  const a = /^\d+$/.test(String(id)) && await one('SELECT a.*, u.name AS va_name FROM accounts a JOIN users u ON u.id=a.va_id WHERE a.id=$1', [Number(id)]);
  if (!a) throw notFound();
  if (user.role === 'va' && a.va_id !== user.id) throw forbid();
  return a;
}
const intId = (v) => { if (!/^\d+$/.test(String(v))) throw notFound(); return Number(v); };

// ---------- Routes ----------
const routes = [];
const route = (method, pattern, role, fn) =>
  routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), role, fn });

route('POST', '/api/login', null, async ({ ip, body, setCookie, secure }) => {
  const a = (await one('SELECT n, until_ms FROM login_attempts WHERE ip=$1', [ip])) || { n: 0, until_ms: 0 };
  if (Number(a.until_ms) > Date.now()) throw new HttpError(429, 'Trop de tentatives, réessaie dans quelques minutes');
  const u = await one('SELECT * FROM users WHERE lower(username)=lower($1)', [String(body.username || '').trim()]);
  if (!u || u.retired || !checkPw(String(body.password || ''), u.password_hash)) {
    let n = a.n + 1; let until = 0;
    if (n >= 8) { until = Date.now() + 5 * 60000; n = 0; }
    await q(`INSERT INTO login_attempts (ip, n, until_ms) VALUES ($1,$2,$3)
             ON CONFLICT (ip) DO UPDATE SET n=EXCLUDED.n, until_ms=EXCLUDED.until_ms`, [ip, n, until]);
    throw new HttpError(401, 'Pseudo ou mot de passe incorrect');
  }
  await q('DELETE FROM login_attempts WHERE ip=$1', [ip]);
  await q(`UPDATE users SET last_login=${NOW_TXT} WHERE id=$1`, [u.id]);
  setCookie(cookieStr(makeToken(u), SESSION_S, secure));
  return { user: pubUser(u) };
});
route('POST', '/api/logout', null, async ({ setCookie, secure }) => {
  setCookie(cookieStr('', 0, secure));
  return { ok: true };
});
route('GET', '/api/me', 'any', async ({ user }) => ({ user: pubUser(user), rate: await getRate(), week: weekRange() }));
route('POST', '/api/me/password', 'any', async ({ user, body, setCookie, secure }) => {
  if (!checkPw(String(body.current || ''), user.password_hash)) throw bad('Mot de passe actuel incorrect');
  if (String(body.next || '').length < 8) throw bad('Nouveau mot de passe : 8 caractères minimum');
  const h = hashPw(body.next);
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [h, user.id]);
  setCookie(cookieStr(makeToken({ id: user.id, password_hash: h }), SESSION_S, secure)); // reste connecté
  return { ok: true };
});

// --- Tableau de bord
route('GET', '/api/stats', 'manager', async () => {
  const week = weekRange();
  const [pays, statusRows, pen, recent] = await Promise.all([
    payRows(week),
    q('SELECT a.status, COUNT(*)::int AS n FROM accounts a JOIN users u ON u.id=a.va_id WHERE u.retired=0 GROUP BY a.status'),
    one('SELECT COALESCE(SUM(amount),0)::float8 AS s FROM penalties WHERE substr(created_at,1,10)>=$1 AND substr(created_at,1,10)<$2', [week.start, week.end]),
    q(`SELECT a.id, a.handle, a.platform, a.status, a.created_at, a.added_by_va, u.name AS va_name
       FROM accounts a JOIN users u ON u.id=a.va_id ORDER BY a.id DESC LIMIT 8`),
  ]);
  const byStatus = {};
  for (const s of STATUSES) byStatus[s] = 0;
  for (const r of statusRows) byStatus[r.status] = r.n;
  return {
    vas: pays.length, accounts: Object.values(byStatus).reduce((a, b) => a + b, 0), byStatus,
    totalPay: pays.reduce((s, p) => s + p.net, 0), penalties: pen.s, week, recent,
  };
});

// --- VA
route('GET', '/api/vas', 'manager', async ({ user, query }) => {
  const retired = query.get('retired') === '1' ? 1 : 0;
  const rows = await q(`SELECT u.*, m.name AS manager_name,
      (SELECT COUNT(*) FROM accounts a WHERE a.va_id=u.id AND a.status IN ${COUNTED_SQL})::int AS counted,
      (SELECT COUNT(*) FROM accounts a WHERE a.va_id=u.id)::int AS total
    FROM users u LEFT JOIN users m ON m.id=u.manager_id
    WHERE u.role='va' AND u.retired=$1 ORDER BY lower(u.name)`, [retired]);
  return { vas: rows.map((r) => ({ ...pubUser(r), manager_name: r.manager_name, counted: r.counted, total: r.total })), me: user.id };
});
route('GET', '/api/managers', 'manager', async () => ({
  managers: await q("SELECT id, name FROM users WHERE role IN ('admin','manager') AND retired=0 ORDER BY name"),
}));
route('POST', '/api/vas', 'manager', async ({ user, body }) => {
  const name = String(body.name || '').trim();
  const username = String(body.username || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!name) throw bad('Nom requis');
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw bad('Pseudo : 3 à 32 caractères (lettres, chiffres, . _ -)');
  if (password.length < 8) throw bad('Mot de passe : 8 caractères minimum');
  if (await one('SELECT 1 AS x FROM users WHERE lower(username)=$1', [username])) throw bad('Ce pseudo existe déjà');
  const r = await one(`INSERT INTO users (username,name,role,password_hash,manager_id,discord,telegram,phone)
    VALUES ($1,$2,'va',$3,$4,$5,$6,$7) RETURNING id`,
    [username, name, hashPw(password), Number(body.manager_id) || user.id,
      String(body.discord || '').trim(), String(body.telegram || '').trim(), String(body.phone || '').trim()]);
  return { id: r.id };
});
route('GET', '/api/vas/:id', 'manager', async ({ params }) => {
  const id = intId(params.id);
  const u = await one("SELECT u.*, m.name AS manager_name FROM users u LEFT JOIN users m ON m.id=u.manager_id WHERE u.id=$1 AND u.role='va'", [id]);
  if (!u) throw notFound();
  const [accounts, pay] = await Promise.all([
    q('SELECT a.*, $2::text AS va_name FROM accounts a WHERE a.va_id=$1 ORDER BY a.id DESC', [id, u.name]),
    payFor(id, weekRange()),
  ]);
  return { va: { ...pubUser(u), manager_name: u.manager_name }, accounts: accounts.map(pubAccount), pay };
});
route('PATCH', '/api/vas/:id', 'manager', async ({ params, body }) => {
  const id = intId(params.id);
  const u = await one("SELECT * FROM users WHERE id=$1 AND role='va'", [id]);
  if (!u) throw notFound();
  const f = (k) => (body[k] !== undefined ? String(body[k]).trim() : u[k]);
  const rate = body.rate === undefined ? u.rate : (body.rate === '' || body.rate === null ? null : Number(body.rate));
  if (rate !== null && (!Number.isFinite(rate) || rate < 0)) throw bad('Tarif invalide');
  await q('UPDATE users SET name=$1, discord=$2, telegram=$3, phone=$4, manager_id=$5, rate=$6, retired=$7 WHERE id=$8',
    [f('name') || u.name, f('discord'), f('telegram'), f('phone'),
      body.manager_id ? Number(body.manager_id) : u.manager_id, rate,
      body.retired === undefined ? u.retired : (body.retired ? 1 : 0), u.id]);
  return { ok: true }; // un VA retiré est déconnecté d'office (la session vérifie « retired »)
});
route('POST', '/api/vas/:id/password', 'manager', async ({ params, body }) => {
  const u = await one("SELECT id FROM users WHERE id=$1 AND role='va'", [intId(params.id)]);
  if (!u) throw notFound();
  if (String(body.password || '').length < 8) throw bad('Mot de passe : 8 caractères minimum');
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [hashPw(body.password), u.id]); // invalide ses sessions
  return { ok: true };
});

// --- Comptes + logins
route('GET', '/api/accounts', 'any', async ({ user, query }) => {
  const where = ['u.retired=0']; const args = [];
  if (user.role === 'va') { args.push(user.id); where.push(`a.va_id=$${args.length}`); }
  else if (query.get('va_id')) { args.push(Number(query.get('va_id')) || 0); where.push(`a.va_id=$${args.length}`); }
  if (query.get('status')) { args.push(query.get('status')); where.push(`a.status=$${args.length}`); }
  const rows = await q(`SELECT a.*, u.name AS va_name FROM accounts a JOIN users u ON u.id=a.va_id
    WHERE ${where.join(' AND ')} ORDER BY a.id DESC`, args);
  return { accounts: rows.map(pubAccount) };
});
route('POST', '/api/accounts', 'any', async ({ user, body }) => {
  const vaId = user.role === 'va' ? user.id : Number(body.va_id);
  const va = vaId && await one("SELECT id FROM users WHERE id=$1 AND role='va' AND retired=0", [vaId]);
  if (!va) throw bad('VA introuvable');
  const lines = user.role !== 'va' && body.bulk ? String(body.url).split(/\r?\n/).map((s) => s.trim()).filter(Boolean) : [body.url];
  if (!lines.length) throw bad('Lien du compte requis');
  const no2fa = body.no2fa ? 1 : 0;
  const secret = no2fa ? '' : cleanTotp(body.totp);
  if (secret && !b32decode(secret).length) throw bad('Clé 2FA invalide');

  const platform = body.platform === undefined || body.platform === '' ? 'instagram' : String(body.platform);
  if (!PLATFORMS[platform]) throw bad('Réseau inconnu');
  const items = lines.map((l) => parseAccount(platform, l));
  const seen = new Set();
  for (const { handle } of items) {
    const k = handle.toLowerCase();
    if (seen.has(k)) throw bad(`${handle} existe déjà`);
    seen.add(k);
  }
  const keysArr = [...seen];
  const dup = await one(`SELECT handle FROM accounts WHERE platform=$1 AND lower(handle) IN (${keysArr.map((_, i) => '$' + (i + 2)).join(',')}) LIMIT 1`, [platform, ...keysArr]);
  if (dup) throw bad(`${dup.handle} existe déjà`);

  const passEnc = enc(body.password || ''); const totpEnc = enc(secret);
  const args = []; const tuples = [];
  for (const { url, handle, login } of items) {
    const b = args.length;
    args.push(vaId, platform, url, handle, String(body.login_user || '').trim() || login, passEnc, totpEnc, no2fa, user.role === 'va' ? 1 : 0);
    tuples.push(`(${Array.from({ length: 9 }, (_, i) => '$' + (b + i + 1)).join(',')})`);
  }
  const created = await q(`INSERT INTO accounts (va_id,platform,url,handle,login_user,password_enc,totp_enc,no2fa,added_by_va)
    VALUES ${tuples.join(',')} RETURNING id`, args); // une seule requête = tout ou rien
  return { ids: created.map((r) => r.id) };
});
route('PATCH', '/api/accounts/:id', 'any', async ({ user, params, body }) => {
  const a = await accountForUser(user, params.id);
  let { url, handle } = a;
  const platform = body.platform === undefined || body.platform === '' ? a.platform : String(body.platform);
  if (!PLATFORMS[platform]) throw bad('Réseau inconnu');
  if ((body.url !== undefined && body.url !== a.url) || platform !== a.platform) {
    ({ url, handle } = parseAccount(platform, body.url !== undefined ? body.url : a.url));
    if (await one('SELECT id FROM accounts WHERE platform=$1 AND lower(handle)=lower($2) AND id<>$3', [platform, handle, a.id])) throw bad(`${handle} existe déjà`);
  }
  const status = body.status === undefined ? a.status : body.status;
  if (!STATUSES.includes(status)) throw bad('Statut invalide');
  if (user.role === 'va' && body.status !== undefined && status !== a.status && !['actif', 'banni'].includes(status)) throw forbid();
  const no2fa = body.no2fa === undefined ? a.no2fa : (body.no2fa ? 1 : 0);
  let totpEnc = a.totp_enc;
  if (body.totp !== undefined && body.totp !== '') {
    const s = cleanTotp(body.totp);
    if (!b32decode(s).length) throw bad('Clé 2FA invalide');
    totpEnc = enc(s);
  }
  if (no2fa) totpEnc = '';
  const pwEnc = body.password !== undefined && body.password !== '' ? enc(body.password) : a.password_enc;
  const followers = body.followers === undefined ? a.followers : (body.followers === '' || body.followers === null ? null : Math.max(0, parseInt(body.followers, 10) || 0));
  await q('UPDATE accounts SET url=$1, handle=$2, platform=$3, status=$4, login_user=$5, password_enc=$6, totp_enc=$7, no2fa=$8, followers=$9, note=$10 WHERE id=$11',
    [url, handle, platform, status, body.login_user === undefined ? a.login_user : String(body.login_user).trim(),
      pwEnc, totpEnc, no2fa, followers, body.note === undefined ? a.note : String(body.note), a.id]);
  return { ok: true };
});
route('DELETE', '/api/accounts/:id', 'manager', async ({ params }) => {
  await q('DELETE FROM accounts WHERE id=$1', [intId(params.id)]);
  return { ok: true };
});
route('GET', '/api/accounts/:id/secret', 'any', async ({ user, params }) => {
  const a = await accountForUser(user, params.id);
  return { login_user: a.login_user, password: dec(a.password_enc), totp_secret: user.role !== 'va' ? dec(a.totp_enc) : undefined };
});
route('GET', '/api/codes', 'any', async ({ user, query }) => {
  const ids = String(query.get('ids') || '').split(',').map(Number).filter(Boolean).slice(0, 300);
  const codes = {};
  if (ids.length) {
    const rows = await q(`SELECT id, va_id, totp_enc FROM accounts WHERE id IN (${ids.map((_, i) => '$' + (i + 1)).join(',')})`, ids);
    for (const a of rows) {
      if ((user.role === 'va' && a.va_id !== user.id) || !a.totp_enc) continue;
      codes[a.id] = totp(dec(a.totp_enc));
    }
  }
  return { codes, remaining: 30 - (Math.floor(Date.now() / 1000) % 30) };
});

// --- Équipe de managers
route('GET', '/api/team', 'admin', async () => ({
  managers: await q("SELECT id, username, name, role, last_login, created_at, retired FROM users WHERE role IN ('admin','manager') ORDER BY (role<>'admin'), retired, lower(name)"),
}));
route('POST', '/api/managers', 'admin', async ({ body }) => {
  const name = String(body.name || '').trim();
  const username = String(body.username || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!name) throw bad('Nom requis');
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw bad('Pseudo : 3 à 32 caractères (lettres, chiffres, . _ -)');
  if (password.length < 8) throw bad('Mot de passe : 8 caractères minimum');
  if (await one('SELECT 1 AS x FROM users WHERE lower(username)=$1', [username])) throw bad('Ce pseudo existe déjà');
  const r = await one("INSERT INTO users (username,name,role,password_hash) VALUES ($1,$2,'manager',$3) RETURNING id",
    [username, name, hashPw(password)]);
  return { id: r.id };
});
route('PATCH', '/api/managers/:id', 'admin', async ({ user, params, body }) => {
  const id = intId(params.id);
  if (id === user.id) throw bad('Tu ne peux pas te retirer toi-même');
  if (!(await one("SELECT 1 AS x FROM users WHERE id=$1 AND role='manager'", [id]))) throw notFound();
  const retired = body.retired ? 1 : 0;
  await q('UPDATE users SET retired=$1 WHERE id=$2', [retired, id]);
  // ses VA passent sous ta responsabilité
  if (retired) await q("UPDATE users SET manager_id=$1 WHERE role='va' AND manager_id=$2", [user.id, id]);
  return { ok: true };
});
route('POST', '/api/managers/:id/password', 'admin', async ({ user, params, body }) => {
  const id = intId(params.id);
  if (id === user.id) throw bad('Pour ton propre mot de passe, utilise « Changer mon mot de passe »');
  if (!(await one("SELECT 1 AS x FROM users WHERE id=$1 AND role='manager'", [id]))) throw notFound();
  if (String(body.password || '').length < 8) throw bad('Mot de passe : 8 caractères minimum');
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [hashPw(body.password), id]);
  return { ok: true };
});

// --- Pénalités
route('GET', '/api/penalties', 'manager', async () => ({
  penalties: await q('SELECT p.*, u.name AS va_name FROM penalties p JOIN users u ON u.id=p.va_id ORDER BY p.id DESC LIMIT 500'),
}));
route('POST', '/api/penalties', 'manager', async ({ body }) => {
  const amount = Number(body.amount);
  const vaId = Number(body.va_id);
  if (!vaId || !(await one("SELECT 1 AS x FROM users WHERE id=$1 AND role='va'", [vaId]))) throw bad('VA introuvable');
  if (!Number.isFinite(amount) || amount <= 0) throw bad('Montant invalide');
  await q('INSERT INTO penalties (va_id, amount, reason) VALUES ($1,$2,$3)', [vaId, amount, String(body.reason || '').trim()]);
  return { ok: true };
});
route('DELETE', '/api/penalties/:id', 'manager', async ({ params }) => {
  await q('DELETE FROM penalties WHERE id=$1', [intId(params.id)]);
  return { ok: true };
});

// --- Paie
route('GET', '/api/pay', 'manager', async ({ query }) => {
  const week = weekRange(Number(query.get('offset')) || 0);
  const [rows, rate] = await Promise.all([payRows(week), getRate()]);
  return { week, rate, rows, total: rows.reduce((s, r) => s + r.net, 0) };
});
route('PATCH', '/api/settings', 'manager', async ({ body }) => {
  const r = Number(body.rate_per_account);
  if (!Number.isFinite(r) || r < 0) throw bad('Tarif invalide');
  await q("UPDATE settings SET value=$1 WHERE key='rate_per_account'", [String(r)]);
  return { ok: true };
});
route('GET', '/api/my-pay', 'va', async ({ user }) => {
  const week = weekRange();
  const [penalties, pay] = await Promise.all([
    q('SELECT amount, reason, created_at FROM penalties WHERE va_id=$1 AND substr(created_at,1,10)>=$2 AND substr(created_at,1,10)<$3 ORDER BY id DESC',
      [user.id, week.start, week.end]),
    payFor(user.id, week),
  ]);
  return { week, ...pay, penalty_list: penalties };
});

// ---------- Point d'entrée ----------
const json = (code, obj, cookies = []) => {
  const h = new Headers({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response(JSON.stringify(obj), { status: code, headers: h });
};

export default async (req, context) => {
  const url = new URL(req.url);
  const cookies = [];
  try {
    const r = routes.find((r) => r.method === req.method && r.re.test(url.pathname));
    if (!r) throw notFound();
    const params = url.pathname.match(r.re).groups || {};
    keys();
    await ensureReady();
    const secure = url.protocol === 'https:';
    let user = null;
    if (r.role) {
      const s = await currentUser(req);
      if (!s) throw new HttpError(401, 'Non connecté');
      user = s.user;
      const allowed = r.role === 'any' || (r.role === 'manager' ? user.role !== 'va' : user.role === r.role);
      if (!allowed) throw forbid();
      // Protection CSRF : les requêtes qui modifient doivent venir de la même origine
      if (req.method !== 'GET') {
        const origin = req.headers.get('origin');
        if (origin && new URL(origin).host !== url.host) throw forbid();
      }
      if (s.refresh) cookies.push(cookieStr(makeToken(user), SESSION_S, secure));
    }
    let body = {};
    if (req.method !== 'GET' && req.method !== 'DELETE') {
      const text = await req.text();
      if (text.length > 1e6) throw bad('Requête trop grosse');
      try { body = text ? JSON.parse(text) : {}; } catch { throw bad('JSON invalide'); }
    }
    const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'inconnue';
    const out = await r.fn({ user, params, query: url.searchParams, body, ip, secure, setCookie: (c) => cookies.push(c) });
    return json(200, out, cookies);
  } catch (e) {
    if (e instanceof HttpError) return json(e.code, { error: e.message });
    if (e && e.code === '23505') return json(400, { error: 'Cet élément existe déjà' });
    console.error(e);
    return json(500, { error: 'Erreur serveur' });
  }
};

export const config = { path: '/api/*' };
