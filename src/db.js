'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// Op Azure App Service (Linux) is alleen /home persistent; daar komt de database standaard terecht.
function defaultDataDir() {
  if (process.env.DATA_DIR) return process.env.DATA_DIR;
  if (process.env.WEBSITE_SITE_NAME && fs.existsSync('/home')) return '/home/data/domaininventory';
  return path.join(__dirname, '..', 'data');
}

function open(dataDir = defaultDataDir()) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'inventory.db'));

  // Geen WAL: /home op App Service is een netwerkshare en WAL vereist gedeeld geheugen.
  db.exec(`
    PRAGMA journal_mode = DELETE;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;

    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id         TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf       TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS computers (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      name           TEXT NOT NULL UNIQUE COLLATE NOCASE,
      last_report_id INTEGER,
      last_seen      TEXT
    );

    CREATE TABLE IF NOT EXISTS reports (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      computer_id    INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
      received_at    TEXT NOT NULL,
      generated_at   TEXT,
      source_ip      TEXT,
      script_version TEXT,
      domain         TEXT,
      part_of_domain INTEGER,
      domain_role    TEXT,
      os             TEXT,
      run_by         TEXT,
      is_admin       INTEGER,
      verdict        TEXT,
      verdict_class  TEXT,
      n_risk         INTEGER NOT NULL DEFAULT 0,
      n_warn         INTEGER NOT NULL DEFAULT 0,
      n_info         INTEGER NOT NULL DEFAULT 0,
      n_ok           INTEGER NOT NULL DEFAULT 0,
      n_apps_system  INTEGER NOT NULL DEFAULT 0,
      n_apps_user    INTEGER NOT NULL DEFAULT 0,
      checks_json    TEXT NOT NULL,
      apps_json      TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS ix_reports_computer ON reports(computer_id, id DESC);
  `);

  return db;
}

function getSetting(db, key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(db, key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, value);
}

function newApiKey() {
  return crypto.randomBytes(24).toString('base64url');
}

function ensureApiKey(db) {
  let key = getSetting(db, 'api_key');
  if (!key) {
    key = newApiKey();
    setSetting(db, 'api_key', key);
  }
  return key;
}

function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = { open, getSetting, setSetting, newApiKey, ensureApiKey, transaction };
