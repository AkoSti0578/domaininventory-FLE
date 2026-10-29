'use strict';

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escBr(value) {
  return esc(value).replace(/\r?\n/g, '<br>');
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return esc(iso);
  return d.toLocaleString('nl-NL', { timeZone: process.env.DISPLAY_TZ || 'Europe/Amsterdam',
    day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const STATUS_CLASS = { Risico: 'risk', Waarschuwing: 'warn', Info: 'info', OK: 'ok' };
const VERDICT_LABEL = { risk: 'Risico', warn: 'Waarschuwing', ok: 'OK' };

function csrfField(csrf) {
  return `<input type="hidden" name="_csrf" value="${esc(csrf)}">`;
}

function layout({ title, user, csrf, body, active = '' }) {
  const nav = user ? `
  <nav>
    <a href="/" class="${active === 'home' ? 'active' : ''}">Overzicht</a>
    <a href="/download" class="${active === 'download' ? 'active' : ''}">Script downloaden</a>
    <a href="/settings" class="${active === 'settings' ? 'active' : ''}">Instellingen</a>
    <span class="spacer"></span>
    <span class="who">${esc(user.username)}</span>
    <form method="post" action="/logout" class="inline">${csrfField(csrf)}<button type="submit" class="link">Uitloggen</button></form>
  </nav>` : '';
  return `<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} - Domein-inventaris</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<header>
  <h1><a href="/">Domein-inventaris</a></h1>
  <p>Risico's en applicaties per computer voor het uit het domein halen</p>
</header>${nav}
<main>
${body}
</main>
<footer><strong>Yellow Spring</strong> &middot; ICT kan slimmer. Het kan.</footer>
<script src="/static/app.js"></script>
</body>
</html>`;
}

function alert(kind, text) {
  return text ? `<div class="alert ${kind}">${esc(text)}</div>` : '';
}

function setupPage({ error, needToken, values = {} }) {
  const body = `
  <div class="card narrow">
    <h2>Eerste beheerder aanmaken</h2>
    <p>Er is nog geen beheerder. Maak het eerste admin-account aan; daarna is deze pagina niet meer beschikbaar.</p>
    ${alert('error', error)}
    <form method="post" action="/setup" class="stack">
      ${needToken ? `<label>Setup-code (app-instelling SETUP_TOKEN)<input name="setup_token" type="password" required autocomplete="off"></label>` : ''}
      <label>Gebruikersnaam<input name="username" required autocomplete="username" value="${esc(values.username)}"></label>
      <label>Wachtwoord (minimaal 12 tekens)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
      <label>Wachtwoord herhalen<input name="password2" type="password" required minlength="12" autocomplete="new-password"></label>
      <button type="submit">Beheerder aanmaken</button>
    </form>
  </div>`;
  return layout({ title: 'Eerste start', body });
}

function loginPage({ error, values = {} }) {
  const body = `
  <div class="card narrow">
    <h2>Inloggen</h2>
    ${alert('error', error)}
    <form method="post" action="/login" class="stack">
      <label>Gebruikersnaam<input name="username" required autocomplete="username" value="${esc(values.username)}" autofocus></label>
      <label>Wachtwoord<input name="password" type="password" required autocomplete="current-password"></label>
      <button type="submit">Inloggen</button>
    </form>
  </div>`;
  return layout({ title: 'Inloggen', body });
}

function countsCell(r) {
  return `<span class="badge risk" title="Risico">${r.n_risk}</span>
    <span class="badge warn" title="Waarschuwing">${r.n_warn}</span>
    <span class="badge info" title="Info">${r.n_info}</span>
    <span class="badge ok" title="OK">${r.n_ok}</span>`;
}

function dashboard({ user, csrf, computers }) {
  const total = computers.length;
  const nRisk = computers.filter(c => c.verdict_class === 'risk').length;
  const nWarn = computers.filter(c => c.verdict_class === 'warn').length;
  const nOk = computers.filter(c => c.verdict_class === 'ok').length;

  const rows = computers.map(c => `
    <tr data-verdict="${esc(c.verdict_class)}">
      <td><a href="/computers/${c.id}"><strong>${esc(c.name)}</strong></a></td>
      <td><span class="badge ${esc(c.verdict_class)}">${esc(VERDICT_LABEL[c.verdict_class] || c.verdict_class)}</span></td>
      <td class="nowrap">${countsCell(c)}</td>
      <td>${esc(c.domain)}</td>
      <td>${esc(c.os)}</td>
      <td>${c.n_apps_system} / ${c.n_apps_user}</td>
      <td>${esc(c.run_by)}${c.is_admin ? '' : ' <span class="badge warn" title="Niet als administrator uitgevoerd">geen admin</span>'}</td>
      <td class="nowrap" data-sort="${esc(c.last_seen)}">${fmtDate(c.last_seen)}</td>
    </tr>`).join('');

  const body = `
  <h2>Overzicht computers</h2>
  <div class="counts">
    <div>Computers <strong>${total}</strong></div>
    <div><span class="badge risk">Risico</span> ${nRisk}</div>
    <div><span class="badge warn">Waarschuwing</span> ${nWarn}</div>
    <div><span class="badge ok">OK</span> ${nOk}</div>
  </div>
  ${total === 0 ? `<div class="alert info">Nog geen resultaten ontvangen. Ga naar <a href="/download">Script downloaden</a> en voer het script uit op een domeincomputer.</div>` : `
  <div class="filters">
    <input id="tableFilter" data-table="computerTable" type="search" placeholder="Zoek op computer, domein, OS of gebruiker...">
    <select id="verdictFilter" data-table="computerTable">
      <option value="">Alle uitkomsten</option>
      <option value="risk">Risico</option><option value="warn">Waarschuwing</option><option value="ok">OK</option>
    </select>
    <span class="rowcount" data-for="computerTable"></span>
  </div>
  <div class="tablewrap">
  <table id="computerTable" class="filterable">
    <thead><tr><th>Computer</th><th>Uitkomst</th><th>R / W / I / OK</th><th>Domein</th><th>Besturingssysteem</th><th>Apps systeem / gebruiker</th><th>Uitgevoerd door</th><th>Laatste rapport</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  </div>`}`;
  return layout({ title: 'Overzicht', user, csrf, body, active: 'home' });
}

function computerPage({ user, csrf, computer, report, history }) {
  const checks = JSON.parse(report.checks_json);
  const apps = JSON.parse(report.apps_json);
  const isLatest = report.id === computer.last_report_id;

  const checkRows = checks.map(c => `
    <tr><td><span class="badge ${STATUS_CLASS[c.status] || 'info'}">${esc(c.status)}</span></td>
    <td>${esc(c.category)}</td><td><strong>${esc(c.check)}</strong></td><td>${escBr(c.detail)}</td><td>${escBr(c.advice)}</td></tr>`).join('');

  const groups = new Map();
  for (const a of apps) {
    const key = `${a.scope}\u0000${a.user}`;
    if (!groups.has(key)) groups.set(key, { scope: a.scope, user: a.user, isDomain: a.isDomainUser, count: 0 });
    groups.get(key).count++;
  }
  const summaryRows = [...groups.values()]
    .sort((x, y) => `${x.scope}${x.user}`.localeCompare(`${y.scope}${y.user}`))
    .map(g => `<tr><td>${esc(g.scope)}</td><td>${esc(g.user)}${g.isDomain ? ' <span class="badge warn">domein</span>' : ''}</td><td>${g.count}</td></tr>`)
    .join('');

  const scopes = [...new Set(apps.map(a => a.scope))].sort();
  const appRows = apps.map(a => `
    <tr data-scope="${esc(a.scope)}"><td><span class="badge ${String(a.scope).startsWith('System') ? 'info' : 'user'}">${esc(a.scope)}</span></td>
    <td>${esc(a.user)}</td><td><strong>${esc(a.name)}</strong></td><td>${esc(a.version)}</td><td>${esc(a.publisher)}</td>
    <td>${esc(a.installDate)}</td><td>${esc(a.architecture)}</td><td>${esc(a.installerType)}</td></tr>`).join('');

  const historyRows = history.map(h => `
    <tr${h.id === report.id ? ' class="current"' : ''}>
      <td><a href="/computers/${computer.id}?report=${h.id}">${fmtDate(h.received_at)}</a></td>
      <td><span class="badge ${esc(h.verdict_class)}">${esc(VERDICT_LABEL[h.verdict_class] || h.verdict_class)}</span></td>
      <td class="nowrap">${countsCell(h)}</td>
      <td>${h.n_apps_system} / ${h.n_apps_user}</td>
      <td>${esc(h.run_by)}</td>
    </tr>`).join('');

  const body = `
  <p class="crumbs"><a href="/">&larr; Overzicht</a></p>
  <h2>${esc(computer.name)}</h2>
  ${isLatest ? '' : `<div class="alert info">Je bekijkt een ouder rapport. <a href="/computers/${computer.id}">Naar het laatste rapport</a></div>`}
  <div class="meta">
    <div><span>Domein</span>${esc(report.domain)}${report.domain_role ? ` (${esc(report.domain_role)})` : ''}</div>
    <div><span>Besturingssysteem</span>${esc(report.os)}</div>
    <div><span>Uitgevoerd door</span>${esc(report.run_by)}${report.is_admin ? '' : ' <span class="badge warn">geen admin</span>'}</div>
    <div><span>Uitgevoerd op / ontvangen</span>${fmtDate(report.generated_at)} / ${fmtDate(report.received_at)}</div>
  </div>
  <div class="actions">
    <a class="button secondary" href="/reports/${report.id}/checks.csv">CSV risico's</a>
    <a class="button secondary" href="/reports/${report.id}/apps.csv">CSV applicaties</a>
    <form method="post" action="/computers/${computer.id}/delete" class="inline" data-confirm="Computer ${esc(computer.name)} en alle rapporten verwijderen?">
      ${csrfField(csrf)}<button type="submit" class="danger">Computer verwijderen</button>
    </form>
  </div>

  <h2 id="risicos">Risico's bij uit domein halen</h2>
  <div class="verdict ${esc(report.verdict_class)}">${esc(report.verdict)}</div>
  <div class="counts">
    <div><span class="badge risk">Risico</span> ${report.n_risk}</div>
    <div><span class="badge warn">Waarschuwing</span> ${report.n_warn}</div>
    <div><span class="badge info">Info</span> ${report.n_info}</div>
    <div><span class="badge ok">OK</span> ${report.n_ok}</div>
  </div>
  <div class="tablewrap">
  <table>
    <thead><tr><th>Status</th><th>Categorie</th><th>Controle</th><th>Bevinding</th><th>Advies</th></tr></thead>
    <tbody>${checkRows}</tbody>
  </table>
  </div>

  <h2 id="applicaties">Applicatie-inventaris</h2>
  <div class="counts">
    <div><span class="badge info">System-wide</span> ${report.n_apps_system}</div>
    <div><span class="badge user">Per gebruiker</span> ${report.n_apps_user}</div>
  </div>
  <h3>Overzicht per scope en gebruiker</h3>
  <div class="tablewrap">
  <table class="small">
    <thead><tr><th>Scope</th><th>Gebruiker</th><th>Aantal apps</th></tr></thead>
    <tbody>${summaryRows}</tbody>
  </table>
  </div>
  <h3>Alle applicaties</h3>
  <div class="filters">
    <input id="tableFilter" data-table="appTable" type="search" placeholder="Zoek op naam, uitgever of gebruiker...">
    <select id="scopeFilter" data-table="appTable"><option value="">Alle scopes</option>${scopes.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('')}</select>
    <span class="rowcount" data-for="appTable"></span>
  </div>
  <div class="tablewrap">
  <table id="appTable" class="filterable">
    <thead><tr><th>Scope</th><th>Gebruiker</th><th>Naam</th><th>Versie</th><th>Uitgever</th><th>Installatiedatum</th><th>Architectuur</th><th>Type</th></tr></thead>
    <tbody>${appRows}</tbody>
  </table>
  </div>

  <h2 id="historie">Historie</h2>
  <div class="tablewrap">
  <table class="small">
    <thead><tr><th>Ontvangen</th><th>Uitkomst</th><th>R / W / I / OK</th><th>Apps sys / user</th><th>Door</th></tr></thead>
    <tbody>${historyRows}</tbody>
  </table>
  </div>`;
  return layout({ title: computer.name, user, csrf, body, active: 'home' });
}

function downloadPage({ user, csrf, baseUrl }) {
  const oneLiner = `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((Invoke-RestMethod -UseBasicParsing -Uri '${baseUrl}/api/script' -Headers @{ 'X-Api-Key' = '<API-SLEUTEL>' }))) -NoOpen`;
  const body = `
  <h2>Script downloaden</h2>
  <p>Het script <code>Invoke-DomainUnjoinAssessment.ps1</code> controleert een domeincomputer op risico's bij het uit het domein halen
  en maakt een applicatie-inventaris. Het maakt lokaal een HTML-rapport en stuurt de resultaten naar deze website.
  Het adres van deze website en de upload-sleutel zijn al in de download ingevuld.</p>
  <div class="actions"><a class="button" href="/download/script">Download Invoke-DomainUnjoinAssessment.ps1</a></div>

  <h3>Uitvoeren op een domeincomputer</h3>
  <ol>
    <li>Kopieer het script naar de computer, bijvoorbeeld naar <code>C:\\Temp</code>.</li>
    <li>Open <strong>Windows PowerShell 5.1 (64-bit) als administrator</strong>.</li>
    <li>Voer uit:
      <pre><code>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Temp\\Invoke-DomainUnjoinAssessment.ps1</code></pre>
    </li>
    <li>Na afloop staat de computer in het <a href="/">overzicht</a>.</li>
  </ol>
  <p>Handige parameters: <code>-NoOpen</code> (rapport niet openen, voor RMM/Intune), <code>-IncludeAppx</code>,
  <code>-IncludeProfileSize</code>, <code>-IncludeSystemComponents</code>, <code>-OutputFolder C:\\Temp</code> en
  <code>-NoUpload</code> (alleen lokaal rapport).</p>

  <h3>Direct uitvoeren zonder downloaden</h3>
  <p>Voor uitrol via RMM of een externe sessie kun je het script ook direct van deze website laden en uitvoeren
  (als administrator). Vervang <code>&lt;API-SLEUTEL&gt;</code> door de upload-sleutel uit <a href="/settings">Instellingen</a>.</p>
  <pre><code>${esc(oneLiner)}</code></pre>
  <p class="muted">De computer moet <code>${esc(baseUrl)}</code> via HTTPS kunnen bereiken.</p>`;
  return layout({ title: 'Script downloaden', user, csrf, body, active: 'download' });
}

function settingsPage({ user, csrf, users, apiKey, message, error }) {
  const userRows = users.map(u => `
    <tr><td>${esc(u.username)}</td><td>${fmtDate(u.created_at)}</td><td>
      ${u.id === user.user_id ? '<span class="muted">jij</span>' : `
      <form method="post" action="/settings/users/${u.id}/delete" class="inline" data-confirm="Beheerder ${esc(u.username)} verwijderen?">
        ${csrfField(csrf)}<button type="submit" class="danger small">Verwijderen</button></form>`}
    </td></tr>`).join('');

  const body = `
  <h2>Instellingen</h2>
  ${alert('success', message)}${alert('error', error)}

  <div class="grid2">
  <section class="card">
    <h3>Upload-sleutel</h3>
    <p>Het script gebruikt deze sleutel om resultaten te versturen. Hij wordt automatisch in de download gezet.
    Na vernieuwen werken eerder gedownloade scripts niet meer.</p>
    <div class="secret"><input type="password" readonly value="${esc(apiKey)}" id="apiKey">
      <button type="button" class="secondary small" data-toggle-secret="apiKey">Toon</button>
      <button type="button" class="secondary small" data-copy="apiKey">Kopieer</button></div>
    <form method="post" action="/settings/apikey" data-confirm="Nieuwe upload-sleutel maken? Eerder gedownloade scripts kunnen dan niet meer uploaden.">
      ${csrfField(csrf)}<button type="submit" class="secondary">Sleutel vernieuwen</button></form>
  </section>

  <section class="card">
    <h3>Wachtwoord wijzigen</h3>
    <form method="post" action="/settings/password" class="stack">
      ${csrfField(csrf)}
      <label>Huidig wachtwoord<input name="current" type="password" required autocomplete="current-password"></label>
      <label>Nieuw wachtwoord (minimaal 12 tekens)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
      <label>Nieuw wachtwoord herhalen<input name="password2" type="password" required minlength="12" autocomplete="new-password"></label>
      <button type="submit">Wachtwoord wijzigen</button>
    </form>
  </section>
  </div>

  <section class="card">
    <h3>Beheerders</h3>
    <table class="small"><thead><tr><th>Gebruikersnaam</th><th>Aangemaakt</th><th></th></tr></thead><tbody>${userRows}</tbody></table>
    <h4>Beheerder toevoegen</h4>
    <form method="post" action="/settings/users" class="stack narrowform">
      ${csrfField(csrf)}
      <label>Gebruikersnaam<input name="username" required autocomplete="off"></label>
      <label>Wachtwoord (minimaal 12 tekens)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
      <button type="submit">Toevoegen</button>
    </form>
  </section>`;
  return layout({ title: 'Instellingen', user, csrf, body, active: 'settings' });
}

function errorPage({ status, message, user, csrf }) {
  return layout({ title: `Fout ${status}`, user, csrf,
    body: `<div class="card narrow"><h2>Fout ${status}</h2><p>${esc(message)}</p><p><a href="/">Terug naar het overzicht</a></p></div>` });
}

module.exports = { esc, layout, setupPage, loginPage, dashboard, computerPage, downloadPage, settingsPage, errorPage };
