// EX SOFTWARE LLC portal - self-service account, trial and device-group state.
//
// backend/data/portal.db already holds the legacy clients/installers tables used
// by the original admin API (and the "Acme Corp" client row). Everything in this
// module is ADDITIVE: only CREATE TABLE IF NOT EXISTS runs here. No existing
// table is altered, renamed, or dropped, and no existing row is touched.
//
// Timestamps are ISO-8601 UTC strings written by the application, so all
// comparisons and ORDER BY clauses are lexicographic and timezone-stable.

'use strict';

const { db } = require('./db');

db.exec(`
CREATE TABLE IF NOT EXISTS portal_users (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  email             TEXT    NOT NULL UNIQUE COLLATE NOCASE,
  name              TEXT    NOT NULL,
  mc_userid         TEXT,                       -- MeshCentral 'user//<domain>/<email>'
  status            TEXT    NOT NULL DEFAULT 'trial',   -- trial | expired | purged | suspended
  plan              TEXT    NOT NULL DEFAULT 'trial',   -- trial | extended
  email_verified    INTEGER NOT NULL DEFAULT 0,
  trial_started_at  TEXT,
  trial_ends_at     TEXT,
  purge_after       TEXT,                       -- trial_ends_at + grace period
  warned_at         TEXT,                       -- trial-ending-soon mail sent
  expired_at        TEXT,
  purged_at         TEXT,
  last_login_at     TEXT,
  created_at        TEXT    NOT NULL,
  updated_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS portal_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL,                 -- confirm | reset
  token_hash  TEXT    NOT NULL UNIQUE,          -- sha256 of the emailed token
  expires_at  TEXT    NOT NULL,
  used_at     TEXT,
  created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS portal_tokens_user_idx ON portal_tokens (user_id, kind);

CREATE TABLE IF NOT EXISTS portal_meshes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
  meshid      TEXT    NOT NULL UNIQUE,          -- 'mesh/<domain>/<base64>'
  name        TEXT    NOT NULL,
  created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS portal_meshes_user_idx ON portal_meshes (user_id);

CREATE TABLE IF NOT EXISTS portal_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  kind        TEXT    NOT NULL,
  detail      TEXT,
  ip          TEXT,
  created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS portal_events_created_idx ON portal_events (created_at);

CREATE TABLE IF NOT EXISTS demo_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL,
  email       TEXT    NOT NULL,
  company     TEXT,
  preferred   TEXT,                               -- preferred demo time (free text)
  notes       TEXT,
  status      TEXT    NOT NULL DEFAULT 'new',     -- new | scheduled | done | closed
  ip          TEXT,
  created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS demo_requests_created_idx ON demo_requests (created_at);
`);

// Migration: `role` separates the company administrator from the client
// accounts an administrator provisions. Additive only - existing rows default to
// 'user' and no existing column is touched.
const portalUserCols = db.prepare('PRAGMA table_info(portal_users)').all();
if (!portalUserCols.some((c) => c.name === 'role')) {
  db.exec("ALTER TABLE portal_users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
}

function nowIso() {
  return new Date().toISOString();
}

function isoPlusHours(hours) {
  return new Date(Date.now() + hours * 3600 * 1000).toISOString();
}

const stmts = {
  // ---- users ----
  insertUser: db.prepare(
    `INSERT INTO portal_users (email, name, mc_userid, status, plan, trial_started_at, trial_ends_at, purge_after, created_at, updated_at)
     VALUES (@email, @name, @mc_userid, @status, @plan, @trial_started_at, @trial_ends_at, @purge_after, @created_at, @updated_at)`
  ),
  // Administrator-provisioned account: no trial window, role fixed to 'user'.
  insertManagedUser: db.prepare(
    `INSERT INTO portal_users (email, name, mc_userid, status, plan, role, email_verified, created_at, updated_at)
     VALUES (@email, @name, @mc_userid, @status, @plan, 'user', 1, @created_at, @updated_at)`
  ),
  getUserByEmail: db.prepare('SELECT * FROM portal_users WHERE email = ? COLLATE NOCASE'),
  getUserById: db.prepare('SELECT * FROM portal_users WHERE id = ?'),
  setUserMcAccount: db.prepare('UPDATE portal_users SET mc_userid = ?, updated_at = ? WHERE id = ?'),
  setUserStatus: db.prepare('UPDATE portal_users SET status = ?, updated_at = ? WHERE id = ?'),
  setUserRole: db.prepare('UPDATE portal_users SET role = ?, updated_at = ? WHERE id = ?'),
  setUserPlan: db.prepare('UPDATE portal_users SET plan = ?, updated_at = ? WHERE id = ?'),
  deleteUser: db.prepare('DELETE FROM portal_users WHERE id = ?'),
  // Operator view: every managed account, newest first, with the number of
  // device groups it owns.
  listAllUsers: db.prepare(
    `SELECT u.*, (SELECT COUNT(*) FROM portal_meshes m WHERE m.user_id = u.id) AS group_count
       FROM portal_users u
      ORDER BY u.created_at DESC, u.id DESC`
  ),
  setUserTrial: db.prepare(
    'UPDATE portal_users SET status = ?, plan = ?, trial_started_at = ?, trial_ends_at = ?, purge_after = ?, warned_at = NULL, expired_at = NULL, purged_at = NULL, updated_at = ? WHERE id = ?'
  ),
  markEmailVerified: db.prepare('UPDATE portal_users SET email_verified = 1, updated_at = ? WHERE id = ?'),
  setUserName: db.prepare('UPDATE portal_users SET name = ?, updated_at = ? WHERE id = ?'),
  setUserEmail: db.prepare('UPDATE portal_users SET email = ?, mc_userid = ?, updated_at = ? WHERE id = ?'),
  touchLogin: db.prepare('UPDATE portal_users SET last_login_at = ?, updated_at = ? WHERE id = ?'),
  setWarned: db.prepare('UPDATE portal_users SET warned_at = ?, updated_at = ? WHERE id = ?'),
  setExpired: db.prepare("UPDATE portal_users SET status = 'expired', expired_at = ?, updated_at = ? WHERE id = ?"),
  setPurged: db.prepare("UPDATE portal_users SET status = 'purged', purged_at = ?, updated_at = ? WHERE id = ?"),

  // ---- trial lifecycle sweeps ----
  listExpiredTrials: db.prepare(
    "SELECT * FROM portal_users WHERE status = 'trial' AND trial_ends_at IS NOT NULL AND trial_ends_at <= ?"
  ),
  listTrialsToWarn: db.prepare(
    "SELECT * FROM portal_users WHERE status = 'trial' AND warned_at IS NULL AND trial_ends_at IS NOT NULL AND trial_ends_at > ? AND trial_ends_at <= ?"
  ),
  listUsersToPurge: db.prepare(
    "SELECT * FROM portal_users WHERE status = 'expired' AND purge_after IS NOT NULL AND purge_after <= ?"
  ),

  // ---- tokens ----
  insertToken: db.prepare(
    'INSERT INTO portal_tokens (user_id, kind, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
  ),
  getToken: db.prepare('SELECT * FROM portal_tokens WHERE token_hash = ? AND kind = ?'),
  useToken: db.prepare('UPDATE portal_tokens SET used_at = ? WHERE id = ?'),
  purgeTokensForUser: db.prepare('DELETE FROM portal_tokens WHERE user_id = ? AND kind = ?'),
  purgeStaleTokens: db.prepare('DELETE FROM portal_tokens WHERE expires_at <= ?'),

  // ---- meshes (device groups owned by a portal user) ----
  insertMesh: db.prepare('INSERT INTO portal_meshes (user_id, meshid, name, created_at) VALUES (?, ?, ?, ?)'),
  getMeshById: db.prepare('SELECT * FROM portal_meshes WHERE id = ?'),
  getMeshByMeshid: db.prepare('SELECT * FROM portal_meshes WHERE meshid = ?'),
  listMeshesForUser: db.prepare('SELECT * FROM portal_meshes WHERE user_id = ? ORDER BY created_at ASC, id ASC'),
  renameMesh: db.prepare('UPDATE portal_meshes SET name = ? WHERE id = ?'),
  deleteMesh: db.prepare('DELETE FROM portal_meshes WHERE id = ?'),
  deleteMeshesForUser: db.prepare('DELETE FROM portal_meshes WHERE user_id = ?'),
  countMeshesForUser: db.prepare('SELECT COUNT(*) AS n FROM portal_meshes WHERE user_id = ?'),

  // ---- audit trail ----
  logEvent: db.prepare('INSERT INTO portal_events (user_id, kind, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)'),
  listEventsForUser: db.prepare('SELECT * FROM portal_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'),

  // ---- demo requests (manual scheduling follows by email) ----
  insertDemoRequest: db.prepare(
    `INSERT INTO demo_requests (name, email, company, preferred, notes, ip, created_at)
     VALUES (@name, @email, @company, @preferred, @notes, @ip, @created_at)`
  ),
  listDemoRequests: db.prepare('SELECT * FROM demo_requests ORDER BY created_at DESC, id DESC LIMIT 200'),
  setDemoRequestStatus: db.prepare('UPDATE demo_requests SET status = ? WHERE id = ?'),
};

module.exports = { authdb: db, stmts, nowIso, isoPlusHours };
