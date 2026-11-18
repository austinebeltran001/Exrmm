// EX SOFTWARE LLC portal - SQLite persistence layer (better-sqlite3).

'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'portal.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS clients (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  meshid      TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS installers (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  token       TEXT NOT NULL UNIQUE,           -- UUID v4 download token
  filename    TEXT NOT NULL,                  -- exagent-setup.exe
  path        TEXT NOT NULL,                  -- absolute path on disk
  size        INTEGER NOT NULL DEFAULT 0,
  sha256      TEXT,
  format      TEXT NOT NULL DEFAULT 'exe',    -- installer format: 'exe' (NSIS) | 'msi' (WiX)
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  downloads   INTEGER NOT NULL DEFAULT 0
);
`);

// Migration: installers.format arrived with the MSI support. Existing rows were
// all NSIS .exe installers, which is exactly the column default.
const installerCols = db.prepare('PRAGMA table_info(installers)').all();
if (!installerCols.some((c) => c.name === 'format')) {
  db.exec("ALTER TABLE installers ADD COLUMN format TEXT NOT NULL DEFAULT 'exe'");
}

const stmts = {
  insertClient: db.prepare('INSERT INTO clients (name, meshid) VALUES (?, ?)'),
  getClientByName: db.prepare('SELECT * FROM clients WHERE name = ?'),
  getClientById: db.prepare('SELECT * FROM clients WHERE id = ?'),
  // One client can now have an .exe and an .msi row, so the join is pinned to
  // the .exe (the historical shape); listInstallersForClient returns variants.
  listClients: db.prepare(`SELECT c.*, i.token, i.filename, i.size, i.sha256, i.format, i.created_at AS installer_created_at, i.downloads
                           FROM clients c LEFT JOIN installers i ON i.client_id = c.id AND i.format = 'exe'
                           ORDER BY c.created_at DESC, c.id DESC`),
  deleteClient: db.prepare('DELETE FROM clients WHERE id = ?'),
  insertInstaller: db.prepare('INSERT INTO installers (client_id, token, filename, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?)'),
  insertInstallerWithFormat: db.prepare('INSERT INTO installers (client_id, token, filename, path, size, sha256, format) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  listInstallersForClient: db.prepare("SELECT * FROM installers WHERE client_id = ? ORDER BY (format = 'exe') DESC, id"),
  getInstallerByToken: db.prepare('SELECT i.*, c.name AS client_name FROM installers i JOIN clients c ON c.id = i.client_id WHERE i.token = ?'),
  bumpDownloads: db.prepare('UPDATE installers SET downloads = downloads + 1 WHERE id = ?'),
  listInstallers: db.prepare('SELECT * FROM installers ORDER BY created_at DESC'),
  deleteInstallersForClient: db.prepare('DELETE FROM installers WHERE client_id = ?'),
};

module.exports = { db, stmts, dbPath };
