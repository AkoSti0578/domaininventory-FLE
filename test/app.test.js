'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const database = require('../src/db');
const { createApp } = require('../server');

const samplePayload = {
  schemaVersion: 1,
  scriptVersion: '1.1.0',
  computer: 'pc-001',
  domain: 'contoso.local',
  partOfDomain: true,
  domainRole: 'Werkstation (domeinlid)',
  os: 'Microsoft Windows 11 Pro (10.0.26100)',
  runBy: 'CONTOSO\\admin',
  isAdmin: true,
  generatedAt: '2026-10-29T10:00:00+01:00',
  checks: [
    { category: 'Services en taken', check: 'Services onder domeinaccount', status: 'Risico', detail: 'Backup [bk] - CONTOSO\\svc', advice: 'Omzetten' },
    { category: 'Algemeen', check: 'Openstaande herstart', status: 'OK', detail: 'Geen <script>alert(1)</script>', advice: '' },
  ],
  applications: [
    { scope: 'System', user: 'Alle gebruikers', userSid: '', isDomainUser: false, name: '7-Zip', version: '24.08', publisher: 'Igor Pavlov', installDate: '2026-01-01', architecture: 'x64', installerType: 'MSI' },
    { scope: 'User', user: 'CONTOSO\\jan', userSid: 'S-1-5-21-1-2-3-1001', isDomainUser: true, name: '=cmd()', version: '1', publisher: 'X', installDate: '', architecture: 'User', installerType: 'EXE/Overig' },
  ],
};

function start(t, env = {}) {
  Object.assign(process.env, env);
  t.after(() => { for (const k of Object.keys(env)) delete process.env[k]; });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inv-'));
  const db = database.open(dir);
  const server = http.createServer(createApp(db));
  return new Promise(resolve => server.listen(0, () => {
    t.after(() => { server.close(); db.close(); fs.rmSync(dir, { recursive: true, force: true }); });
    resolve({ base: `http://127.0.0.1:${server.address().port}`, db });
  }));
}

function form(obj) {
  return { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(obj).toString() };
}

test('eerste start, login, upload en overzicht', async t => {
  const { base, db } = await start(t);

  let res = await fetch(`${base}/`, { redirect: 'manual' });
  assert.strictEqual(res.headers.get('location'), '/setup');

  res = await fetch(`${base}/setup`, form({ username: 'admin', password: 'kort', password2: 'kort' }));
  assert.strictEqual(res.status, 400);

  res = await fetch(`${base}/setup`, form({ username: 'admin', password: 'een-lang-wachtwoord', password2: 'een-lang-wachtwoord' }));
  assert.strictEqual(res.status, 303);
  const cookie = res.headers.get('set-cookie').split(';')[0];

  // Setup is daarna dicht
  res = await fetch(`${base}/setup`, form({ username: 'x', password: 'een-lang-wachtwoord', password2: 'een-lang-wachtwoord' }));
  assert.strictEqual(res.headers.get('location'), '/login');
  assert.strictEqual(db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 1);

  // Upload zonder en met sleutel
  res = await fetch(`${base}/api/reports`, { method: 'POST', body: JSON.stringify(samplePayload) });
  assert.strictEqual(res.status, 401);
  const key = database.getSetting(db, 'api_key');
  res = await fetch(`${base}/api/reports`, { method: 'POST', headers: { 'X-Api-Key': key, 'Content-Type': 'application/json' }, body: JSON.stringify(samplePayload) });
  assert.strictEqual(res.status, 201);
  const { computerId, reportId } = await res.json();

  // Overzicht en detail
  res = await fetch(`${base}/`, { headers: { cookie } });
  let html = await res.text();
  assert.match(html, /PC-001/);
  assert.match(html, /badge risk/);

  res = await fetch(`${base}/computers/${computerId}`, { headers: { cookie } });
  html = await res.text();
  assert.match(html, /7-Zip/);
  assert.ok(!html.includes('<script>alert(1)'), 'detail moet ge-escaped zijn');

  res = await fetch(`${base}/reports/${reportId}/apps.csv`, { headers: { cookie } });
  const csv = await res.text();
  assert.match(csv, /"'=cmd\(\)"/);

  // Script-download bevat URL en sleutel
  res = await fetch(`${base}/download/script`, { headers: { cookie } });
  const script = await res.text();
  assert.ok(script.includes(`[string]$ApiKey = '${key}'`));
  assert.ok(script.includes(`[string]$ReportUrl = '${base}'`));
  assert.ok(script.includes('\r\n'));

  res = await fetch(`${base}/api/script`, { headers: { 'X-Api-Key': key } });
  assert.strictEqual(res.status, 200);

  // Formulier zonder CSRF-token wordt geweigerd
  res = await fetch(`${base}/settings/apikey`, { ...form({}), headers: { ...form({}).headers, cookie } });
  assert.strictEqual(res.status, 403);
});

test('setup vereist SETUP_TOKEN als die is ingesteld', async t => {
  const { base } = await start(t, { SETUP_TOKEN: 'geheim-123' });
  let res = await fetch(`${base}/setup`, form({ username: 'admin', password: 'een-lang-wachtwoord', password2: 'een-lang-wachtwoord' }));
  assert.strictEqual(res.status, 400);
  res = await fetch(`${base}/setup`, form({ setup_token: 'geheim-123', username: 'admin', password: 'een-lang-wachtwoord', password2: 'een-lang-wachtwoord' }));
  assert.strictEqual(res.status, 303);
});
