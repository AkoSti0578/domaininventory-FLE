'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const database = require('./src/db');
const auth = require('./src/auth');
const views = require('./src/views');

const PORT = Number(process.env.PORT) || 8080;
const REPORT_RETENTION = Math.max(1, Number(process.env.REPORT_RETENTION) || 25);
const MAX_REPORT_BYTES = 25 * 1024 * 1024;
const MAX_FORM_BYTES = 64 * 1024;
const SCRIPT_NAME = 'Invoke-DomainUnjoinAssessment.ps1';
const SCRIPT_PATH = path.join(__dirname, 'scripts', SCRIPT_NAME);
const PUBLIC_DIR = path.join(__dirname, 'public');
const STATIC_TYPES = { '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
const VALID_STATUS = new Set(['Risico', 'Waarschuwing', 'Info', 'OK']);
const STATUS_ORDER = { Risico: 0, Waarschuwing: 1, Info: 2, OK: 3 };

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function createApp(db) {
  database.ensureApiKey(db);

  // --- Hulpfuncties voor request/response ---
  function parseCookies(req) {
    const out = {};
    for (const part of String(req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
  }

  function proto(req) {
    return String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() || (req.socket.encrypted ? 'https' : 'http');
  }

  function baseUrl(req) {
    if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/+$/, '');
    return `${proto(req)}://${req.headers.host}`;
  }

  function clientIp(req) {
    // Azure zet het client-IP (met poort) in X-Forwarded-For
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    return (xff || req.socket.remoteAddress || '').replace(/:\d+$/, '');
  }

  function sessionCookie(req, value, maxAgeSec) {
    const secure = proto(req) === 'https' ? '; Secure' : '';
    return `sid=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure}`;
  }

  function send(res, status, body, headers = {}) {
    res.writeHead(status, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      ...headers,
    });
    res.end(body);
  }

  function redirect(res, location, headers = {}) {
    res.writeHead(303, { Location: location, 'Cache-Control': 'no-store', ...headers });
    res.end();
  }

  function json(res, status, obj) {
    send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8' });
  }

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', chunk => {
        size += chunk.length;
        if (size > limit) {
          reject(new HttpError(413, 'Verzoek is te groot.'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  async function readForm(req) {
    const buf = await readBody(req, MAX_FORM_BYTES);
    return Object.fromEntries(new URLSearchParams(buf.toString('utf8')));
  }

  function hasAdmin() {
    return db.prepare('SELECT COUNT(*) AS n FROM users').get().n > 0;
  }

  // Formulieren: CSRF-token uit de sessie plus Origin-controle
  function checkCsrf(req, session, form) {
    const origin = req.headers.origin;
    if (origin && origin !== baseUrl(req)) throw new HttpError(403, 'Ongeldige herkomst van het formulier.');
    if (!auth.safeEqual(form._csrf, session.csrf)) throw new HttpError(403, 'Formulier verlopen. Laad de pagina opnieuw.');
  }

  // --- Rapport-upload ---
  function str(value, max) {
    if (value === null || value === undefined) return null;
    const s = String(value);
    return s.length > max ? s.slice(0, max) : s;
  }

  function normalizeReport(p) {
    if (!p || typeof p !== 'object') throw new HttpError(400, 'Ongeldige JSON.');
    const computer = str(p.computer, 64);
    if (!computer || !/^[A-Za-z0-9._-]+$/.test(computer)) throw new HttpError(400, 'Ongeldige computernaam.');
    if (!Array.isArray(p.checks) || p.checks.length > 1000) throw new HttpError(400, 'Ongeldige lijst met controles.');
    if (!Array.isArray(p.applications) || p.applications.length > 50000) throw new HttpError(400, 'Ongeldige applicatielijst.');

    const checks = p.checks.map(c => ({
      category: str(c?.category, 200) || '',
      check: str(c?.check, 300) || '',
      status: VALID_STATUS.has(c?.status) ? c.status : 'Info',
      detail: str(c?.detail, 20000) || '',
      advice: str(c?.advice, 4000) || '',
    })).sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]
      || a.category.localeCompare(b.category) || a.check.localeCompare(b.check));

    const applications = p.applications.map(a => ({
      scope: str(a?.scope, 100) || '',
      user: str(a?.user, 300) || '',
      userSid: str(a?.userSid, 200) || '',
      isDomainUser: a?.isDomainUser === true,
      name: str(a?.name, 500) || '',
      version: str(a?.version, 200) || '',
      publisher: str(a?.publisher, 500) || '',
      installDate: str(a?.installDate, 50) || '',
      architecture: str(a?.architecture, 50) || '',
      installerType: str(a?.installerType, 50) || '',
      installLocation: str(a?.installLocation, 1000) || '',
    }));

    const count = s => checks.filter(c => c.status === s).length;
    const n = { risk: count('Risico'), warn: count('Waarschuwing'), info: count('Info'), ok: count('OK') };
    let verdictClass = 'ok';
    let verdict = 'Geen blokkerende risico\'s gevonden.';
    if (n.risk > 0) { verdictClass = 'risk'; verdict = 'Niet uit het domein halen voordat de risico\'s zijn opgelost.'; }
    else if (n.warn > 0) { verdictClass = 'warn'; verdict = 'Uit het domein halen is mogelijk na het afhandelen van de waarschuwingen.'; }

    return {
      computer: computer.toUpperCase(),
      generatedAt: str(p.generatedAt, 64),
      scriptVersion: str(p.scriptVersion, 32),
      domain: str(p.domain, 300),
      partOfDomain: p.partOfDomain === true ? 1 : 0,
      domainRole: str(p.domainRole, 100),
      os: str(p.os, 300),
      runBy: str(p.runBy, 300),
      isAdmin: p.isAdmin === true ? 1 : 0,
      verdict, verdictClass, n,
      nAppsSystem: applications.filter(a => a.scope.startsWith('System')).length,
      nAppsUser: applications.filter(a => a.scope.startsWith('User')).length,
      checks, applications,
    };
  }

  function storeReport(r, ip) {
    return database.transaction(db, () => {
      const now = new Date().toISOString();
      db.prepare('INSERT INTO computers (name) VALUES (?) ON CONFLICT(name) DO NOTHING').run(r.computer);
      const computerId = db.prepare('SELECT id FROM computers WHERE name = ?').get(r.computer).id;
      const { lastInsertRowid } = db.prepare(`
        INSERT INTO reports (computer_id, received_at, generated_at, source_ip, script_version, domain, part_of_domain,
          domain_role, os, run_by, is_admin, verdict, verdict_class, n_risk, n_warn, n_info, n_ok,
          n_apps_system, n_apps_user, checks_json, apps_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        computerId, now, r.generatedAt, ip, r.scriptVersion, r.domain, r.partOfDomain, r.domainRole, r.os, r.runBy,
        r.isAdmin, r.verdict, r.verdictClass, r.n.risk, r.n.warn, r.n.info, r.n.ok, r.nAppsSystem, r.nAppsUser,
        JSON.stringify(r.checks), JSON.stringify(r.applications));
      const reportId = Number(lastInsertRowid);
      db.prepare('UPDATE computers SET last_report_id = ?, last_seen = ? WHERE id = ?').run(reportId, now, computerId);
      db.prepare(`DELETE FROM reports WHERE computer_id = ? AND id NOT IN
        (SELECT id FROM reports WHERE computer_id = ? ORDER BY id DESC LIMIT ?)`).run(computerId, computerId, REPORT_RETENTION);
      return { computerId, reportId };
    });
  }

  function apiKeyValid(req) {
    return auth.safeEqual(req.headers['x-api-key'], database.getSetting(db, 'api_key'));
  }

  function scriptText(req) {
    const url = baseUrl(req).replace(/'/g, "''");
    const key = database.getSetting(db, 'api_key').replace(/'/g, "''");
    return fs.readFileSync(SCRIPT_PATH, 'utf8')
      .replace("'__REPORT_URL__'", `'${url}'`)
      .replace("'__API_KEY__'", `'${key}'`)
      .replace(/\r?\n/g, '\r\n');
  }

  // --- CSV-export (zelfde opmaak als het script: puntkomma, UTF-8 met BOM) ---
  function csv(rows, columns) {
    const cell = v => {
      let s = String(v ?? '');
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // geen formules uitvoeren in Excel
      return `"${s.replace(/"/g, '""')}"`;
    };
    const lines = [columns.map(c => cell(c[0])).join(';')];
    for (const r of rows) lines.push(columns.map(c => cell(r[c[1]])).join(';'));
    return '﻿' + lines.join('\r\n') + '\r\n';
  }

  // --- Routes ---
  async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    const method = req.method;

    if (p === '/healthz') return send(res, 200, 'ok', { 'Content-Type': 'text/plain' });

    if (p.startsWith('/static/') && method === 'GET') {
      const file = path.join(PUBLIC_DIR, path.basename(p));
      const type = STATIC_TYPES[path.extname(file)];
      if (!type || !fs.existsSync(file)) throw new HttpError(404, 'Niet gevonden.');
      return send(res, 200, fs.readFileSync(file), { 'Content-Type': type, 'Cache-Control': 'public, max-age=3600' });
    }

    // API voor het script (sleutel in header X-Api-Key)
    if (p === '/api/reports' && method === 'POST') {
      if (!apiKeyValid(req)) return json(res, 401, { error: 'Ongeldige API-sleutel.' });
      const body = await readBody(req, MAX_REPORT_BYTES);
      let payload;
      try { payload = JSON.parse(body.toString('utf8').replace(/^﻿/, '')); }
      catch { throw new HttpError(400, 'Ongeldige JSON.'); }
      const report = normalizeReport(payload);
      const ids = storeReport(report, clientIp(req));
      console.log(`Rapport ontvangen van ${report.computer} (${clientIp(req)}), rapport-ID ${ids.reportId}`);
      return json(res, 201, { ok: true, ...ids });
    }
    if (p === '/api/script' && method === 'GET') {
      if (!apiKeyValid(req)) return json(res, 401, { error: 'Ongeldige API-sleutel.' });
      return send(res, 200, scriptText(req), { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    if (p.startsWith('/api/')) throw new HttpError(404, 'Niet gevonden.');

    // Eerste start: beheerder aanmaken
    if (!hasAdmin()) {
      if (p !== '/setup') return redirect(res, '/setup');
      const needToken = Boolean(process.env.SETUP_TOKEN);
      if (method === 'GET') return send(res, 200, views.setupPage({ needToken }));
      if (method !== 'POST') throw new HttpError(405, 'Methode niet toegestaan.');
      const form = await readForm(req);
      const values = { username: form.username };
      const fail = error => send(res, 400, views.setupPage({ error, needToken, values }));
      if (needToken && !auth.safeEqual(form.setup_token, process.env.SETUP_TOKEN)) return fail('Onjuiste setup-code.');
      const err = auth.validateUsername(form.username) || auth.validatePassword(form.password)
        || (form.password !== form.password2 ? 'De wachtwoorden zijn niet gelijk.' : null);
      if (err) return fail(err);
      const userId = database.transaction(db, () => {
        if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n > 0) return null;
        return Number(db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
          .run(form.username, auth.hashPassword(form.password), new Date().toISOString()).lastInsertRowid);
      });
      if (!userId) return redirect(res, '/login');
      console.log(`Eerste beheerder aangemaakt: ${form.username}`);
      const sid = auth.createSession(db, userId);
      return redirect(res, '/', { 'Set-Cookie': sessionCookie(req, sid, auth.SESSION_TTL_MS / 1000) });
    }
    if (p === '/setup') return redirect(res, '/login');

    const cookies = parseCookies(req);
    const session = auth.getSession(db, cookies.sid);

    if (p === '/login') {
      if (session) return redirect(res, '/');
      if (method === 'GET') return send(res, 200, views.loginPage({}));
      if (method !== 'POST') throw new HttpError(405, 'Methode niet toegestaan.');
      const ip = clientIp(req);
      const form = await readForm(req);
      const values = { username: form.username };
      if (auth.isBlocked(ip)) {
        return send(res, 429, views.loginPage({ error: 'Te veel mislukte pogingen. Probeer het over 15 minuten opnieuw.', values }));
      }
      const user = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(String(form.username || ''));
      if (!user || !auth.verifyPassword(String(form.password || ''), user.password_hash)) {
        auth.registerFailure(ip);
        return send(res, 401, views.loginPage({ error: 'Onjuiste gebruikersnaam of wachtwoord.', values }));
      }
      auth.clearFailures(ip);
      const sid = auth.createSession(db, user.id);
      return redirect(res, '/', { 'Set-Cookie': sessionCookie(req, sid, auth.SESSION_TTL_MS / 1000) });
    }

    if (!session) {
      if (method === 'GET') return redirect(res, '/login');
      throw new HttpError(401, 'Niet ingelogd.');
    }
    const ctx = { user: session, csrf: session.csrf };

    let form = null;
    if (method === 'POST') {
      form = await readForm(req);
      checkCsrf(req, session, form);
    }

    if (p === '/logout' && method === 'POST') {
      auth.deleteSession(db, session.id);
      return redirect(res, '/login', { 'Set-Cookie': sessionCookie(req, '', 0) });
    }

    if (p === '/' && method === 'GET') {
      const computers = db.prepare(`
        SELECT c.id, c.name, c.last_seen, r.domain, r.os, r.run_by, r.is_admin, r.verdict_class,
               r.n_risk, r.n_warn, r.n_info, r.n_ok, r.n_apps_system, r.n_apps_user
        FROM computers c JOIN reports r ON r.id = c.last_report_id
        ORDER BY CASE r.verdict_class WHEN 'risk' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, c.name`).all();
      return send(res, 200, views.dashboard({ ...ctx, computers }));
    }

    let m;
    if ((m = p.match(/^\/computers\/(\d+)$/)) && method === 'GET') {
      const computer = db.prepare('SELECT * FROM computers WHERE id = ?').get(Number(m[1]));
      if (!computer) throw new HttpError(404, 'Computer niet gevonden.');
      const reportId = Number(url.searchParams.get('report')) || computer.last_report_id;
      const report = db.prepare('SELECT * FROM reports WHERE id = ? AND computer_id = ?').get(reportId, computer.id);
      if (!report) throw new HttpError(404, 'Rapport niet gevonden.');
      const history = db.prepare(`SELECT id, received_at, verdict_class, n_risk, n_warn, n_info, n_ok, n_apps_system, n_apps_user, run_by
        FROM reports WHERE computer_id = ? ORDER BY id DESC`).all(computer.id);
      return send(res, 200, views.computerPage({ ...ctx, computer, report, history }));
    }
    if ((m = p.match(/^\/computers\/(\d+)\/delete$/)) && method === 'POST') {
      db.prepare('DELETE FROM computers WHERE id = ?').run(Number(m[1]));
      return redirect(res, '/');
    }
    if ((m = p.match(/^\/reports\/(\d+)\/(checks|apps)\.csv$/)) && method === 'GET') {
      const report = db.prepare(`SELECT r.*, c.name FROM reports r JOIN computers c ON c.id = r.computer_id WHERE r.id = ?`)
        .get(Number(m[1]));
      if (!report) throw new HttpError(404, 'Rapport niet gevonden.');
      const stamp = report.received_at.slice(0, 16).replace(/[-:]/g, '').replace('T', '_');
      const body = m[2] === 'checks'
        ? csv(JSON.parse(report.checks_json), [['Categorie', 'category'], ['Controle', 'check'], ['Status', 'status'], ['Detail', 'detail'], ['Advies', 'advice']])
        : csv(JSON.parse(report.apps_json), [['Scope', 'scope'], ['User', 'user'], ['UserSid', 'userSid'], ['Name', 'name'], ['Version', 'version'],
          ['Publisher', 'publisher'], ['InstallDate', 'installDate'], ['Architecture', 'architecture'], ['InstallerType', 'installerType'], ['InstallLocation', 'installLocation']]);
      const name = `DomainUnjoin_${report.name}_${stamp}_${m[2] === 'checks' ? 'risicos' : 'applicaties'}.csv`;
      return send(res, 200, body, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}"` });
    }

    if (p === '/download' && method === 'GET') {
      return send(res, 200, views.downloadPage({ ...ctx, baseUrl: baseUrl(req) }));
    }
    if (p === '/download/script' && method === 'GET') {
      return send(res, 200, scriptText(req), {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${SCRIPT_NAME}"`,
      });
    }

    if (p.startsWith('/settings')) {
      const renderSettings = (status, extra) => send(res, status, views.settingsPage({
        ...ctx, ...extra,
        users: db.prepare('SELECT id, username, created_at FROM users ORDER BY username').all(),
        apiKey: database.getSetting(db, 'api_key'),
      }));

      if (p === '/settings' && method === 'GET') {
        const msg = { pw: 'Wachtwoord gewijzigd.', user: 'Beheerder toegevoegd.', del: 'Beheerder verwijderd.', key: 'Nieuwe upload-sleutel gemaakt. Download het script opnieuw.' };
        return renderSettings(200, { message: msg[url.searchParams.get('ok')] });
      }
      if (p === '/settings/apikey' && method === 'POST') {
        database.setSetting(db, 'api_key', database.newApiKey());
        return redirect(res, '/settings?ok=key');
      }
      if (p === '/settings/password' && method === 'POST') {
        const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(session.user_id);
        if (!auth.verifyPassword(String(form.current || ''), user.password_hash)) return renderSettings(400, { error: 'Huidig wachtwoord is onjuist.' });
        const err = auth.validatePassword(form.password) || (form.password !== form.password2 ? 'De nieuwe wachtwoorden zijn niet gelijk.' : null);
        if (err) return renderSettings(400, { error: err });
        db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(auth.hashPassword(form.password), session.user_id);
        db.prepare('DELETE FROM sessions WHERE user_id = ? AND id <> ?').run(session.user_id, session.id);
        return redirect(res, '/settings?ok=pw');
      }
      if (p === '/settings/users' && method === 'POST') {
        const err = auth.validateUsername(form.username) || auth.validatePassword(form.password);
        if (err) return renderSettings(400, { error: err });
        if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(form.username)) return renderSettings(400, { error: 'Deze gebruikersnaam bestaat al.' });
        db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
          .run(form.username, auth.hashPassword(form.password), new Date().toISOString());
        return redirect(res, '/settings?ok=user');
      }
      if ((m = p.match(/^\/settings\/users\/(\d+)\/delete$/)) && method === 'POST') {
        const id = Number(m[1]);
        if (id === session.user_id) return renderSettings(400, { error: 'Je kunt jezelf niet verwijderen.' });
        db.prepare('DELETE FROM users WHERE id = ?').run(id);
        return redirect(res, '/settings?ok=del');
      }
    }

    throw new HttpError(404, 'Pagina niet gevonden.');
  }

  return async function app(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
    if (proto(req) === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      await handle(req, res);
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      if (res.headersSent) return res.end();
      const message = status === 500 ? 'Er ging iets mis op de server.' : err.message;
      if (req.url.startsWith('/api/')) return json(res, status, { error: message });
      send(res, status, views.errorPage({ status, message }));
    }
  };
}

if (require.main === module) {
  const db = database.open();
  http.createServer(createApp(db)).listen(PORT, () => {
    console.log(`Domein-inventaris luistert op poort ${PORT}`);
  });
}

module.exports = { createApp };
