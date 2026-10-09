'use strict';
// ---------- Utilitaires ----------
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const STATUS = { actif: 'Actif', chauffe: 'En chauffe', shadowban: 'Shadowban', banni: 'Banni' };
let me = null, appInfo = {};

async function api(url, opts = {}) {
  const o = { method: opts.method || 'GET', headers: {}, credentials: 'same-origin' };
  if (opts.body !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(opts.body); }
  const r = await fetch(url, o);
  let d = {}; try { d = await r.json(); } catch {}
  if (r.status === 401 && url !== '/api/login' && me) { me = null; render(); }
  if (!r.ok) throw new Error(d.error || 'Erreur');
  return d;
}
const post = (u, body) => api(u, { method: 'POST', body });
const patch = (u, body) => api(u, { method: 'PATCH', body });
const del = (u) => api(u, { method: 'DELETE' });

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 2200);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copié'); }
  catch { const i = document.createElement('input'); i.value = text; document.body.appendChild(i); i.select(); document.execCommand('copy'); i.remove(); toast('Copié'); }
}
const dateOf = (s) => {
  s = String(s);
  if (s.length === 10) return new Date(s + 'T12:00:00'); // date seule : midi local, évite le décalage de jour
  return new Date(s.replace(' ', 'T') + (s.includes('T') ? '' : 'Z'));
};
const fmtShort = (s) => s ? dateOf(s).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' }) : '—';
const fmtLong = (s) => s ? dateOf(s).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';
const fmtTime = (s) => s ? dateOf(s).toLocaleString('fr-FR', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : 'Jamais';
const money = (n) => Number(n || 0).toLocaleString('fr-FR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' $';
const weekLabel = (w) => `${fmtShort(w.start)} → ${fmtShort(w.last)}`;
const COLORS = ['#10b981', '#f97316', '#8b5cf6', '#ef4444', '#3b82f6', '#ec4899', '#14b8a6', '#eab308'];
function avatar(name, big) {
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const ini = name.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
  return `<span class="av" style="background:${COLORS[h % COLORS.length]};${big ? 'width:52px;height:52px;font-size:20px' : ''}">${esc(ini)}</span>`;
}
const badge = (s) => `<span class="badge ${s}">${STATUS[s] || s}</span>`;
function statusSelect(a, only) {
  const list = only || Object.keys(STATUS);
  return `<select class="st" data-status="${a.id}">${list.map(s => `<option value="${s}" ${s === a.status ? 'selected' : ''}>${STATUS[s]}</option>`).join('')}</select>`;
}
function field(label, name, o = {}) {
  const t = o.type || 'text';
  const inp = t === 'textarea'
    ? `<textarea name="${name}" rows="${o.rows || 4}" placeholder="${esc(o.ph || '')}" ${o.req ? 'required' : ''}>${esc(o.value || '')}</textarea>`
    : `<input name="${name}" type="${t}" value="${esc(o.value ?? '')}" placeholder="${esc(o.ph || '')}" ${o.req ? 'required' : ''} ${o.step ? `step="${o.step}"` : ''} ${t === 'password' ? 'autocomplete="new-password"' : 'autocomplete="off"'}>`;
  return `<label class="f">${esc(label)}${inp}${o.help ? `<small>${esc(o.help)}</small>` : ''}</label>`;
}
function selectField(label, name, options, value) {
  return `<label class="f">${esc(label)}<select name="${name}">${options.map(([v, l]) => `<option value="${esc(v)}" ${String(v) === String(value) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>`;
}
const genPw = () => Array.from(crypto.getRandomValues(new Uint8Array(12)), b => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 54]).join('');

function modal({ title, sub = '', body, submit = 'Enregistrer', onSubmit }) {
  const ov = document.createElement('div'); ov.className = 'ov';
  ov.innerHTML = `<form class="modal" autocomplete="off"><h2>${esc(title)}</h2><p class="sub">${esc(sub)}</p>${body}<p class="err"></p>
    <div class="foot"><button type="button" class="btn ghost" data-close>${submit ? 'Annuler' : 'Fermer'}</button>${submit ? `<button class="btn primary">${esc(submit)}</button>` : ''}</div></form>`;
  document.body.appendChild(ov);
  const form = $('form', ov), err = $('.err', ov), btn = $('.btn.primary', ov);
  const close = () => ov.remove();
  ov.addEventListener('mousedown', e => { if (e.target === ov) close(); });
  $('[data-close]', ov).onclick = close;
  form.onsubmit = async (e) => {
    e.preventDefault(); if (!onSubmit) return;
    const data = Object.fromEntries(new FormData(form));
    form.querySelectorAll('input[type=checkbox]').forEach(c => (data[c.name] = c.checked));
    btn.disabled = true; err.textContent = '';
    try { await onSubmit(data, form); close(); } catch (ex) { err.textContent = ex.message; btn.disabled = false; }
  };
  const first = form.querySelector('input:not([type=checkbox]),select,textarea'); if (first) first.focus();
  return { close, form };
}

// ---------- Codes 2FA en direct ----------
let codeBusy = false, lastPeriod = -1;
setInterval(async () => {
  const rem = 30 - (Math.floor(Date.now() / 1000) % 30);
  document.querySelectorAll('[data-ring]').forEach(e => (e.textContent = rem));
  const els = [...document.querySelectorAll('[data-code]')];
  if (!els.length || codeBusy) return;
  const period = Math.floor(Date.now() / 30000);
  if (period === lastPeriod && els.every(e => e.dataset.ok)) return;
  codeBusy = true; lastPeriod = period;
  try {
    const ids = [...new Set(els.map(e => e.dataset.code))];
    const r = await api('/api/codes?ids=' + ids.join(','));
    els.forEach(e => { const c = r.codes[e.dataset.code]; e.dataset.raw = c || ''; e.textContent = c ? c.slice(0, 3) + ' ' + c.slice(3) : '—'; e.dataset.ok = 1; });
  } catch {}
  codeBusy = false;
}, 1000);
const codeCell = (a) => a.has_2fa
  ? `<span class="code mono"><span data-code="${a.id}">······</span><span class="ring" data-ring>30</span><button class="icon gray" data-act="copycode" data-id="${a.id}" title="Copier le code">⧉</button></span>`
  : `<span class="muted">${a.no2fa ? 'Sans 2FA' : '—'}</span>`;
const secrets = {};
async function secretOf(id) { return secrets[id] || (secrets[id] = await api(`/api/accounts/${id}/secret`)); }
const pwCell = (a) => a.has_password
  ? `<span class="nowrap"><span class="mono" data-pw="${a.id}">••••••••</span> <button class="icon gray" data-act="eye" data-id="${a.id}" title="Afficher">👁</button><button class="icon gray" data-act="copypw" data-id="${a.id}" title="Copier">⧉</button></span>`
  : '<span class="muted">—</span>';

// ---------- Modales de comptes ----------
function accountForm(a, role) {
  const st = role === 'va' ? ['actif', 'banni'] : Object.keys(STATUS);
  return `${field('Lien du compte', 'url', { value: a ? a.url : '', ph: 'https://www.instagram.com/pseudo', req: true, help: a ? '' : 'Ouvre le profil dans Instagram → Partager le profil → Copier le lien.' })}
    ${field('Login (identifiant de connexion)', 'login_user', { value: a ? a.login_user : '', ph: 'pseudo, e-mail ou téléphone utilisé pour se connecter' })}
    ${field('Mot de passe', 'password', { type: 'password', ph: a && a.has_password ? 'Laisser vide pour ne pas changer' : 'Mot de passe du compte (facultatif)' })}
    ${field('Clé 2FA', 'totp', { ph: a && a.has_2fa ? 'Laisser vide pour ne pas changer' : 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567', help: 'La clé donnée par Instagram quand tu actives l\'appli d\'authentification (Paramètres → Sécurité → Authentification à 2 facteurs).' })}
    <label class="chk"><input type="checkbox" name="no2fa" ${a && a.no2fa ? 'checked' : ''}> Ce compte n'a pas de 2FA</label>
    ${a ? selectField('Statut', 'status', st.map(s => [s, STATUS[s]]), a.status) : ''}
    ${a && role === 'manager' ? field('Abonnés', 'followers', { type: 'number', value: a.followers ?? '' }) : ''}`;
}
function editAccount(a) {
  modal({
    title: 'Modifier ' + a.handle, body: accountForm(a, me.role), submit: 'Enregistrer',
    onSubmit: async (d) => { await patch('/api/accounts/' + a.id, d); delete secrets[a.id]; toast('Compte mis à jour'); render(); },
  });
}
async function showLogin(id, handle) {
  const s = await secretOf(id);
  modal({
    title: 'Login de ' + handle, submit: null,
    body: `<div class="kv"><span>Identifiant</span><span class="mono">${esc(s.login_user || '—')} <button type="button" class="icon gray" data-act="copytext" data-text="${esc(s.login_user)}">⧉</button></span>
      <span>Mot de passe</span><span class="mono">${esc(s.password || '—')} ${s.password ? `<button type="button" class="icon gray" data-act="copytext" data-text="${esc(s.password)}">⧉</button>` : ''}</span>
      <span>Clé 2FA</span><span class="mono" style="word-break:break-all">${esc(s.totp_secret || '—')}</span>
      <span>Code 2FA</span><span class="code mono"><span data-code="${id}">······</span><span class="ring" data-ring>30</span></span></div>`,
  });
}
function addLoginModal(vas, vaId) {
  modal({
    title: 'Enregistrer un login', sub: 'Le compte et ses accès sont enregistrés (chiffrés) et visibles par le VA et son manager.',
    body: (me.role === 'manager' ? selectField('VA', 'va_id', vas.map(v => [v.id, v.name]), vaId) : '') + accountForm(null, me.role),
    submit: 'Ajouter',
    onSubmit: async (d) => { await post('/api/accounts', d); toast('Login enregistré'); render(); },
  });
}

// ---------- Actions (délégation) ----------
const actions = {
  async eye(t) {
    const el = $(`[data-pw="${t.dataset.id}"]`);
    if (el.dataset.shown) { el.textContent = '••••••••'; delete el.dataset.shown; return; }
    el.textContent = (await secretOf(t.dataset.id)).password; el.dataset.shown = 1;
  },
  async copypw(t) { copy((await secretOf(t.dataset.id)).password); },
  copycode(t) { const e = $(`[data-code="${t.dataset.id}"]`); if (e && e.dataset.raw) copy(e.dataset.raw); },
  copytext(t) { copy(t.dataset.text); },
  logout: async () => { await post('/api/logout'); me = null; location.hash = ''; render(); },
  async pwd() {
    modal({
      title: 'Changer mon mot de passe',
      body: field('Mot de passe actuel', 'current', { type: 'password', req: true }) + field('Nouveau mot de passe', 'next', { type: 'password', req: true, help: '8 caractères minimum' }),
      onSubmit: async (d) => { await post('/api/me/password', d); toast('Mot de passe modifié'); },
    });
  },
  async viewlogin(t) { showLogin(t.dataset.id, t.dataset.handle); },
  async editacc(t) { const a = JSON.parse(t.dataset.acc); editAccount(a); },
  async delacc(t) {
    if (!confirm(`Supprimer définitivement ${t.dataset.handle} ?`)) return;
    await del('/api/accounts/' + t.dataset.id); toast('Compte supprimé'); render();
  },
  async delpen(t) { if (confirm('Supprimer cette pénalité ?')) { await del('/api/penalties/' + t.dataset.id); render(); } },
  genpw(t) { const i = t.closest('form').querySelector('[name=password]'); i.type = 'text'; i.value = genPw(); },
};
document.addEventListener('click', async (e) => {
  const t = e.target.closest('[data-act]'); if (!t) return;
  e.preventDefault(); e.stopPropagation();
  try { await actions[t.dataset.act](t); } catch (ex) { toast(ex.message); }
});
document.addEventListener('change', async (e) => {
  const s = e.target.closest('[data-status]'); if (!s) return;
  try { await patch('/api/accounts/' + s.dataset.status, { status: s.value }); toast('Statut mis à jour'); render(); }
  catch (ex) { toast(ex.message); render(); }
});

// ---------- Connexion ----------
function renderLogin() {
  $('#app').innerHTML = `<div class="login"><form class="modal" id="lf">
    <div class="brand" style="padding:0 0 18px"><i>▮</i><span>CRM <b>Manager</b></span></div>
    <h2>Connexion</h2><p class="sub">Manager ou VA : connecte-toi avec ton pseudo.</p>
    ${field('Pseudo', 'username', { req: true })}${field('Mot de passe', 'password', { type: 'password', req: true })}
    <p class="err"></p><button class="btn primary" style="width:100%;justify-content:center">Se connecter</button></form></div>`;
  $('#lf').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const d = Object.fromEntries(new FormData(e.target));
      me = (await post('/api/login', d)).user; location.hash = '#/'; render();
    } catch (ex) { $('.err').textContent = ex.message; }
  };
}

// ---------- Interface manager ----------
const NAV = [['/', 'Tableau de bord', '▦'], ['/vas', 'VA', '☺'], ['/comptes', 'Comptes', '▯'], ['/logins', 'Logins', '🔑'], ['/penalites', 'Pénalités', '⊘'], ['/paie', 'Paie', '＄']];
async function shell(active) {
  let count = '';
  try { count = (await api('/api/stats')).accounts; } catch {}
  $('#app').innerHTML = `<div class="shell"><aside class="side">
    <div class="brand"><i>▮</i><span>CRM <b>Manager</b></span></div>
    <nav class="nav">${NAV.map(([p, l, i]) => `<a href="#${p}" class="${p === active ? 'on' : ''}"><span>${i}</span>${l}${p === '/comptes' && count !== '' ? `<span class="count">${count}</span>` : ''}</a>`).join('')}</nav>
    <div class="me">${avatar(me.name)}<div class="who"><b>${esc(me.name)}</b><span>Manager</span></div>
      <button class="icon gray" data-act="pwd" title="Changer mon mot de passe">🔑</button><button class="icon gray" data-act="logout" title="Déconnexion">⇥</button></div>
  </aside><main class="main" id="view"></main></div>`;
  return $('#view');
}

async function viewDashboard(v) {
  const s = await api('/api/stats');
  v.innerHTML = `<div class="head"><div><h1>Tableau de bord</h1><p class="muted">Semaine du ${weekLabel(s.week)}</p></div></div>
    <div class="grid g4" style="margin-bottom:18px">
      <div class="stat"><span>VA dans l'équipe</span><b>${s.vas}</b></div>
      <div class="stat"><span>Comptes au total</span><b>${s.accounts}</b></div>
      <div class="stat"><span>Actifs</span><b class="green">${s.byStatus.actif}</b></div>
      <div class="stat"><span>En chauffe</span><b class="amber">${s.byStatus.chauffe}</b></div>
      <div class="stat"><span>Shadowban</span><b style="color:var(--violet)">${s.byStatus.shadowban}</b></div>
      <div class="stat"><span>Bannis</span><b class="red">${s.byStatus.banni}</b></div>
      <div class="stat"><span>Pénalités (semaine)</span><b>${money(s.penalties)}</b></div>
      <div class="stat"><span>Paie à verser (semaine)</span><b class="green">${money(s.totalPay)}</b></div></div>
    <div class="card"><div class="ch"><h2>Derniers comptes ajoutés</h2></div><div class="tw"><table>
      <tr><th>Compte</th><th>VA</th><th>Statut</th><th>Ajouté le</th></tr>
      ${s.recent.map(a => `<tr><td>${esc(a.handle)} ${a.added_by_va ? '<span class="tag">Ajouté par le VA</span>' : ''}</td><td>${esc(a.va_name)}</td><td>${badge(a.status)}</td><td>${fmtShort(a.created_at)}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">Aucun compte pour le moment</td></tr>'}
    </table></div></div>`;
}

const vasUI = { scope: 'mine', retired: false, q: '' };
async function viewVas(v) {
  const r = await api('/api/vas?retired=' + (vasUI.retired ? 1 : 0));
  const draw = () => {
    const q = vasUI.q.toLowerCase();
    const list = r.vas.filter(x => (vasUI.scope === 'all' || x.manager_id === me.id) &&
      (!q || [x.name, x.username, x.discord, x.telegram, x.phone].join(' ').toLowerCase().includes(q)));
    $('#vatable').innerHTML = `<tr><th>VA</th><th>Manager</th><th>Comptes</th><th>Téléphone</th><th>Telegram</th><th>Arrivé le</th></tr>` +
      (list.map(x => `<tr class="click" onclick="location.hash='#/vas/${x.id}'"><td><span style="display:flex;align-items:center;gap:12px">${avatar(x.name)}<span><b>${esc(x.name)}</b><br><span class="muted" style="font-size:12px">@${esc(x.username)}</span></span></span></td>
        <td><span class="dot"></span> ${esc(x.manager_name || '—')}</td>
        <td><b class="${x.counted ? 'green' : 'red'}">${x.counted}</b> <span class="muted">compte${x.counted > 1 ? 's' : ''}</span></td>
        <td class="muted">${esc(x.phone || 'Non renseigné')}</td><td class="muted">${esc(x.telegram || '—')}</td><td>${fmtLong(x.created_at)}</td></tr>`).join('') ||
        '<tr><td colspan="6" class="empty">Aucun VA</td></tr>');
  };
  v.innerHTML = `<div class="head"><div><h1>VA</h1><p class="muted">${r.vas.length} ${vasUI.retired ? 'VA retiré(s)' : 'VA dans l\'équipe'}</p></div>
    <div class="actions"><button class="btn primary" data-act="addva">＋ Ajouter un VA</button></div></div>
    <div class="pills"><span class="pill ${vasUI.scope === 'mine' ? 'on' : ''}" data-scope="mine">Mes VA</span><span class="pill ${vasUI.scope === 'all' ? 'on' : ''}" data-scope="all">Tous</span>
      <span class="pill ${!vasUI.retired ? 'on' : ''}" data-ret="0">Dans l'équipe</span><span class="pill ${vasUI.retired ? 'on' : ''}" data-ret="1">Retirés</span></div>
    <input class="search" id="q" placeholder="Nom, pseudo, Discord, Telegram, téléphone…" value="${esc(vasUI.q)}" style="margin-bottom:14px">
    <div class="card"><div class="tw"><table id="vatable"></table></div></div>`;
  draw();
  $('#q').oninput = (e) => { vasUI.q = e.target.value; draw(); };
  v.querySelectorAll('[data-scope]').forEach(p => (p.onclick = () => { vasUI.scope = p.dataset.scope; render(); }));
  v.querySelectorAll('[data-ret]').forEach(p => (p.onclick = () => { vasUI.retired = p.dataset.ret === '1'; render(); }));
}
actions.addva = async () => {
  const { managers } = await api('/api/managers');
  modal({
    title: 'Ajouter un VA', sub: 'Crée son accès : il pourra se connecter et ajouter ses comptes.',
    body: field('Nom du VA', 'name', { req: true }) + field('Pseudo de connexion', 'username', { req: true, help: 'Lettres minuscules, chiffres, . _ -' }) +
      `<div style="display:flex;gap:8px;align-items:flex-end">${field('Mot de passe', 'password', { type: 'text', req: true, help: '8 caractères minimum' }).replace('<label class="f">', '<label class="f" style="flex:1">')}<button type="button" class="btn sm" data-act="genpw" style="margin-bottom:14px">Générer</button></div>` +
      selectField('Manager', 'manager_id', managers.map(m => [m.id, m.name]), me.id) +
      field('Discord', 'discord') + field('Telegram', 'telegram') + field('Téléphone', 'phone'),
    submit: 'Créer le VA',
    onSubmit: async (d) => {
      const r = await post('/api/vas', d);
      alert(`Accès créé.\n\nPseudo : ${d.username}\nMot de passe : ${d.password}\n\nTransmets-les au VA.`);
      location.hash = '#/vas/' + r.id; render();
    },
  });
};

async function viewVaDetail(v, id) {
  const { va, accounts, pay } = await api('/api/vas/' + id);
  const counted = accounts.filter(a => a.status !== 'banni').length;
  v.innerHTML = `<p><a href="#/vas" class="muted">← VA</a></p>
    <div class="head"><div style="display:flex;gap:16px;align-items:center">${avatar(va.name, true)}<div><h1 style="margin:0">${esc(va.name)}</h1>
      ${va.retired ? '<span class="badge banni">Retiré</span>' : '<span class="badge">Actif</span>'} <span class="dot"></span> ${esc(va.manager_name || '')}</div></div>
      <div class="actions"><button class="btn" data-act="editva">✎ Modifier</button>
      <button class="btn danger" data-act="retireva">${va.retired ? 'Réintégrer' : 'Retirer de l\'équipe'}</button></div></div>
    <div class="grid g2"><div>
      <div class="card"><div class="ch"><h2>Infos</h2></div><div class="cb">
        <div class="kv"><span>Telegram</span><span>${esc(va.telegram || '—')}</span><span>Discord</span><span>${esc(va.discord || '—')}</span>
        <span>Téléphone</span><span>${esc(va.phone || '—')}</span><span>Arrivé le</span><span>${fmtLong(va.created_at)}</span></div></div></div>
      <div class="card"><div class="ch"><h2>Espace VA</h2><p>Le VA y ajoute ses comptes (lien, login, mot de passe, 2FA) et voit sa paie de la semaine.</p></div><div class="cb">
        <div class="kv"><span>Pseudo</span><span class="mono">${esc(va.username)}</span><span>Connexion</span><span>${fmtTime(va.last_login)}</span></div>
        <button class="btn sm" data-act="newpw" style="margin-top:10px">🔑 Nouveau mot de passe</button></div></div>
      <div class="card"><div class="ch"><h2>Paie de la semaine</h2><p>${weekLabel((await api('/api/me')).week)}</p></div><div class="cb">
        <div class="kv"><span>Comptes</span><span>${pay.counted} × ${money(pay.rate)}</span><span>Pénalités</span><span class="red">− ${money(pay.penalties)}</span><span>À payer</span><b class="green">${money(pay.net)}</b></div></div></div>
    </div>
    <div class="card"><div class="ch" style="display:flex;justify-content:space-between;align-items:center;gap:12px">
      <div><h2>Comptes Instagram</h2><p>Comptent : actifs, en chauffe et shadowban</p><div class="big green">${pay.counted} <small>compte${pay.counted > 1 ? 's' : ''}</small></div></div>
      <button class="btn primary" data-act="addaccs">＋ Ajouter des comptes</button></div>
      <div class="tw"><table><tr><th>Compte</th><th>Login</th><th>Statut</th><th>Abonnés</th><th>Ajouté le</th><th></th></tr>
      ${accounts.map(a => `<tr><td><a href="${esc(a.url)}" target="_blank" rel="noopener"><b>${esc(a.handle)}</b></a> ${a.added_by_va ? '<span class="tag">Ajouté par le VA</span>' : ''}</td>
        <td class="muted mono">${esc(a.login_user || '—')}${a.has_password ? ' 🔒' : ''}${a.has_2fa ? ' 2FA' : ''}</td><td>${statusSelect(a)}</td><td class="muted">${a.followers ?? '—'}</td><td>${fmtShort(a.created_at)}</td>
        <td class="right nowrap"><button class="icon" data-act="viewlogin" data-id="${a.id}" data-handle="${esc(a.handle)}" title="Voir le login">🔑</button>
        <button class="icon" data-act="editacc" data-acc="${esc(JSON.stringify(a))}" title="Modifier">✎</button>
        <button class="icon red" data-act="delacc" data-id="${a.id}" data-handle="${esc(a.handle)}" title="Supprimer">🗑</button></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Aucun compte pour l\'instant</td></tr>'}
      </table></div></div></div>`;
  actions.editva = () => modal({
    title: 'Modifier le VA', body: field('Nom', 'name', { value: va.name, req: true }) + field('Discord', 'discord', { value: va.discord }) + field('Telegram', 'telegram', { value: va.telegram }) +
      field('Téléphone', 'phone', { value: va.phone }) + field('Tarif par compte ($/semaine)', 'rate', { type: 'number', step: '0.01', value: va.rate ?? '', ph: 'Vide = tarif général', help: 'Laisse vide pour utiliser le tarif général (page Paie).' }),
    onSubmit: async (d) => { await patch('/api/vas/' + id, d); render(); },
  });
  actions.retireva = async () => {
    if (!confirm(va.retired ? `Réintégrer ${va.name} ?` : `Retirer ${va.name} de l'équipe ? Son accès sera coupé.`)) return;
    await patch('/api/vas/' + id, { retired: !va.retired }); render();
  };
  actions.newpw = () => modal({
    title: 'Nouveau mot de passe', sub: `Pour ${va.name}. Il sera déconnecté.`,
    body: `<div style="display:flex;gap:8px;align-items:flex-end">${field('Mot de passe', 'password', { type: 'text', req: true }).replace('<label class="f">', '<label class="f" style="flex:1">')}<button type="button" class="btn sm" data-act="genpw" style="margin-bottom:14px">Générer</button></div>`,
    onSubmit: async (d) => { await post(`/api/vas/${id}/password`, d); alert(`Nouveau mot de passe de ${va.username} :\n\n${d.password}`); },
  });
  actions.addaccs = () => modal({
    title: 'Ajouter des comptes', sub: `Pour ${va.name}. Pour enregistrer aussi le login, le mot de passe et la 2FA, utilise la page « Logins ».`,
    body: field('Liens des comptes (un par ligne)', 'url', { type: 'textarea', rows: 6, ph: 'https://www.instagram.com/pseudo1\nhttps://www.instagram.com/pseudo2', req: true }),
    submit: 'Ajouter',
    onSubmit: async (d) => { await post('/api/accounts', { va_id: id, url: d.url, bulk: true }); toast('Comptes ajoutés'); render(); },
  });
}

async function viewComptes(v) {
  const [{ accounts }, { vas }] = await Promise.all([api('/api/accounts'), api('/api/vas')]);
  const f = { va: '', status: '', q: '' };
  const draw = () => {
    const list = accounts.filter(a => (!f.va || a.va_id == f.va) && (!f.status || a.status === f.status) && (!f.q || (a.handle + a.login_user).toLowerCase().includes(f.q.toLowerCase())));
    $('#t').innerHTML = `<tr><th>Compte</th><th>VA</th><th>Statut</th><th>Abonnés</th><th>Ajouté le</th><th></th></tr>` + (list.map(a => `<tr>
      <td><a href="${esc(a.url)}" target="_blank" rel="noopener"><b>${esc(a.handle)}</b></a> ${a.added_by_va ? '<span class="tag">Ajouté par le VA</span>' : ''}</td>
      <td><a href="#/vas/${a.va_id}">${esc(a.va_name)}</a></td><td>${statusSelect(a)}</td><td class="muted">${a.followers ?? '—'}</td><td>${fmtShort(a.created_at)}</td>
      <td class="right nowrap"><button class="icon" data-act="viewlogin" data-id="${a.id}" data-handle="${esc(a.handle)}">🔑</button>
      <button class="icon" data-act="editacc" data-acc="${esc(JSON.stringify(a))}">✎</button>
      <button class="icon red" data-act="delacc" data-id="${a.id}" data-handle="${esc(a.handle)}">🗑</button></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Aucun compte</td></tr>');
    $('#n').textContent = list.length + ' compte' + (list.length > 1 ? 's' : '');
  };
  v.innerHTML = `<div class="head"><div><h1>Comptes</h1><p class="muted" id="n"></p></div></div>
    <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap"><input class="search" id="q" placeholder="Rechercher un compte…">
      <select id="fv" style="width:200px"><option value="">Tous les VA</option>${vas.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('')}</select>
      <select id="fs" style="width:180px"><option value="">Tous les statuts</option>${Object.entries(STATUS).map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</select></div>
    <div class="card"><div class="tw"><table id="t"></table></div></div>`;
  draw();
  $('#q').oninput = e => { f.q = e.target.value; draw(); }; $('#fv').onchange = e => { f.va = e.target.value; draw(); }; $('#fs').onchange = e => { f.status = e.target.value; draw(); };
}

async function viewLogins(v) {
  const [{ accounts }, { vas }] = await Promise.all([api('/api/accounts'), api('/api/vas')]);
  const f = { va: '', q: '' };
  const draw = () => {
    const list = accounts.filter(a => (!f.va || a.va_id == f.va) && (!f.q || (a.handle + a.login_user + a.va_name).toLowerCase().includes(f.q.toLowerCase())));
    $('#t').innerHTML = `<tr><th>Compte</th><th>VA</th><th>Login</th><th>Mot de passe</th><th>Code 2FA</th><th></th></tr>` + (list.map(a => `<tr>
      <td><a href="${esc(a.url)}" target="_blank" rel="noopener"><b>${esc(a.handle)}</b></a><br>${badge(a.status)}</td><td>${esc(a.va_name)}</td>
      <td class="mono">${esc(a.login_user || '—')}</td><td>${pwCell(a)}</td><td>${codeCell(a)}</td>
      <td class="right nowrap"><button class="icon" data-act="editacc" data-acc="${esc(JSON.stringify(a))}" title="Modifier le login">✎</button></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Aucun login enregistré</td></tr>');
  };
  v.innerHTML = `<div class="head"><div><h1>Logins</h1><p class="muted">Identifiants de chaque compte, chiffrés. Les codes 2FA se renouvellent toutes les 30 secondes.</p></div>
    <div class="actions"><button class="btn primary" id="addlogin">＋ Enregistrer un login</button></div></div>
    <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap"><input class="search" id="q" placeholder="Rechercher un compte, un login…">
      <select id="fv" style="width:200px"><option value="">Tous les VA</option>${vas.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('')}</select></div>
    <div class="card"><div class="tw"><table id="t"></table></div></div>`;
  draw();
  $('#q').oninput = e => { f.q = e.target.value; draw(); }; $('#fv').onchange = e => { f.va = e.target.value; draw(); };
  $('#addlogin').onclick = () => addLoginModal(vas, f.va || (vas[0] && vas[0].id));
}

async function viewPen(v) {
  const [{ penalties }, { vas }] = await Promise.all([api('/api/penalties'), api('/api/vas')]);
  v.innerHTML = `<div class="head"><div><h1>Pénalités</h1><p class="muted">Déduites de la paie de la semaine en cours.</p></div>
    <div class="actions"><button class="btn primary" id="addp">＋ Ajouter une pénalité</button></div></div>
    <div class="card"><div class="tw"><table><tr><th>VA</th><th>Montant</th><th>Raison</th><th>Date</th><th></th></tr>
    ${penalties.map(p => `<tr><td>${esc(p.va_name)}</td><td class="red">− ${money(p.amount)}</td><td>${esc(p.reason || '—')}</td><td>${fmtLong(p.created_at)}</td>
      <td class="right"><button class="icon red" data-act="delpen" data-id="${p.id}">🗑</button></td></tr>`).join('') || '<tr><td colspan="5" class="empty">Aucune pénalité</td></tr>'}</table></div></div>`;
  $('#addp').onclick = () => modal({
    title: 'Ajouter une pénalité',
    body: selectField('VA', 'va_id', vas.map(x => [x.id, x.name])) + field('Montant ($)', 'amount', { type: 'number', step: '0.01', req: true }) + field('Raison', 'reason'),
    onSubmit: async (d) => { await post('/api/penalties', d); render(); },
  });
}

let payOffset = 0;
async function viewPay(v) {
  const r = await api('/api/pay?offset=' + payOffset);
  v.innerHTML = `<div class="head"><div><h1>Paie</h1><p class="muted">Semaine du ${weekLabel(r.week)} (samedi → vendredi)</p></div>
    <div class="actions"><button class="btn" id="pp">←</button><button class="btn" id="pn" ${payOffset >= 0 ? 'disabled' : ''}>→</button></div></div>
    <div class="card"><div class="cb" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap"><label class="f" style="margin:0">Tarif par compte et par semaine ($)
      <input id="rate" type="number" step="0.01" value="${r.rate}" style="width:160px"></label><button class="btn" id="saver">Enregistrer le tarif</button></div></div>
    <div class="card"><div class="tw"><table><tr><th>VA</th><th>Comptes</th><th>Tarif</th><th>Brut</th><th>Pénalités</th><th class="right">À payer</th></tr>
    ${r.rows.map(x => `<tr><td><a href="#/vas/${x.va_id}">${esc(x.name)}</a></td><td>${x.counted}</td><td>${money(x.rate)}</td><td>${money(x.gross)}</td><td class="red">− ${money(x.penalties)}</td><td class="right green"><b>${money(x.net)}</b></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Aucun VA</td></tr>'}
    <tr><td colspan="5" class="right"><b>Total</b></td><td class="right green"><b>${money(r.total)}</b></td></tr></table></div></div>
    <p class="muted">Les comptes comptés sont ceux dont le statut est actif, en chauffe ou shadowban (état actuel). Les pénalités sont celles de la semaine affichée.</p>`;
  $('#pp').onclick = () => { payOffset--; render(); }; $('#pn').onclick = () => { payOffset++; render(); };
  $('#saver').onclick = async () => { try { await patch('/api/settings', { rate_per_account: $('#rate').value }); toast('Tarif enregistré'); render(); } catch (e) { toast(e.message); } };
}

async function renderManager() {
  const h = (location.hash.replace(/^#/, '') || '/').split('/'); // ['', page, id]
  const page = '/' + (h[1] || '');
  const v = await shell(page === '/' ? '/' : (NAV.find(n => n[0] === page) ? page : '/vas'));
  if (page === '/') return viewDashboard(v);
  if (page === '/vas') return h[2] ? viewVaDetail(v, h[2]) : viewVas(v);
  if (page === '/comptes') return viewComptes(v);
  if (page === '/logins') return viewLogins(v);
  if (page === '/penalites') return viewPen(v);
  if (page === '/paie') return viewPay(v);
  location.hash = '#/';
}

// ---------- Espace VA ----------
async function renderVA() {
  const [{ accounts }, pay] = await Promise.all([api('/api/accounts'), api('/api/my-pay')]);
  const by = (s) => accounts.filter(a => a.status === s).length;
  $('#app').innerHTML = `<div class="va-wrap"><div class="va-top"><div class="brand"><i>▮</i><div><b style="color:var(--text)">${esc(me.name)}</b><br><span class="muted" style="font-weight:400;font-size:12px">Mon espace</span></div></div>
      <span><button class="icon gray" data-act="pwd" title="Changer mon mot de passe">🔑</button><button class="btn sm ghost" data-act="logout">⇥ Déconnexion</button></span></div>
    <div class="vcard"><div class="r" style="display:block"><span class="muted">Mes comptes qui comptent</span>
      <div class="big green">${pay.counted} <small>compte${pay.counted > 1 ? 's' : ''}</small></div>
      <span class="muted">${by('actif')} actif${by('actif') > 1 ? 's' : ''} · ${by('chauffe')} en chauffe · ${by('shadowban')} shadowban · ${by('banni')} banni${by('banni') > 1 ? 's' : ''}</span></div></div>
    <div class="vcard"><div class="r pay-row" id="payhead"><div><b>Ma paie de la semaine</b><br><span class="muted" style="font-size:12px">${weekLabel(pay.week)}</span></div><span class="pay-big">${money(pay.net)} <small class="muted">▾</small></span></div>
      <div id="paydet" hidden><div class="r"><span class="muted">${pay.counted} compte${pay.counted > 1 ? 's' : ''} × ${money(pay.rate)}</span><span>${money(pay.gross)}</span></div>
      ${pay.penalty_list.map(p => `<div class="r"><span class="muted">Pénalité${p.reason ? ' · ' + esc(p.reason) : ''}</span><span class="red">− ${money(p.amount)}</span></div>`).join('')}</div></div>
    <button class="btn primary" id="addacc" style="width:100%;justify-content:center;padding:14px;margin-bottom:22px">＋ Ajouter un compte</button>
    <h2 style="margin-bottom:12px">Mes comptes (${accounts.length})</h2>
    ${accounts.map(a => `<div class="vcard"><div class="t"><div><a href="${esc(a.url)}" target="_blank" rel="noopener"><b>${esc(a.handle)}</b></a><br><span class="muted" style="font-size:12px">${esc(a.login_user ? 'Login : ' + a.login_user : 'Login non renseigné')}</span></div>
        <span>${badge(a.status)} <button class="icon gray" data-act="editacc" data-acc="${esc(JSON.stringify(a))}" title="Modifier">✎</button></span></div>
      <div class="r"><span class="muted">Mot de passe</span>${pwCell(a)}</div>
      <div class="r"><span class="muted">Code 2FA</span>${codeCell(a)}</div></div>`).join('') || '<div class="empty">Aucun compte. Ajoute ton premier compte avec le bouton ci-dessus.</div>'}</div>`;
  $('#payhead').onclick = () => ($('#paydet').hidden = !$('#paydet').hidden);
  $('#addacc').onclick = () => addLoginModal([], null);
}

// ---------- Démarrage ----------
async function render() {
  try {
    if (!me) return renderLogin();
    return me.role === 'va' ? await renderVA() : await renderManager();
  } catch (e) { toast(e.message); }
}
window.addEventListener('hashchange', () => me && me.role === 'manager' && render());
(async () => {
  try { const d = await api('/api/me'); me = d.user; appInfo = d; } catch { me = null; }
  render();
})();
