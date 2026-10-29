'use strict';

const crypto = require('node:crypto');

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, hashB64] = parts;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = crypto.scryptSync(password, Buffer.from(saltB64, 'base64'), expected.length,
    { N: Number(N), r: Number(r), p: Number(p) });
  return crypto.timingSafeEqual(actual, expected);
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 12) return 'Het wachtwoord moet minimaal 12 tekens lang zijn.';
  if (password.length > 256) return 'Het wachtwoord is te lang.';
  return null;
}

function validateUsername(username) {
  if (typeof username !== 'string' || !/^[A-Za-z0-9._@-]{3,64}$/.test(username)) {
    return 'Gebruikersnaam: 3-64 tekens, alleen letters, cijfers en . _ @ -';
  }
  return null;
}

function createSession(db, userId) {
  const id = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  db.prepare('INSERT INTO sessions (id, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)')
    .run(id, userId, csrf, Date.now() + SESSION_TTL_MS);
  return id;
}

function getSession(db, id) {
  if (!id) return null;
  const row = db.prepare(`
    SELECT s.id, s.csrf, s.expires_at, u.id AS user_id, u.username
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.id = ?`).get(id);
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
    return null;
  }
  return row;
}

function deleteSession(db, id) {
  if (id) db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// Eenvoudige rem op brute force: max 10 mislukte pogingen per IP per 15 minuten.
const failures = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;

function isBlocked(ip) {
  const f = failures.get(ip);
  if (!f) return false;
  if (Date.now() - f.first > WINDOW_MS) { failures.delete(ip); return false; }
  return f.count >= MAX_FAILURES;
}

function registerFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > WINDOW_MS) failures.set(ip, { first: Date.now(), count: 1 });
  else f.count++;
}

function clearFailures(ip) {
  failures.delete(ip);
}

module.exports = {
  SESSION_TTL_MS, hashPassword, verifyPassword, validatePassword, validateUsername,
  createSession, getSession, deleteSession, safeEqual, isBlocked, registerFailure, clearFailures,
};
