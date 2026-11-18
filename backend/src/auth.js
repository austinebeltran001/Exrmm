// EX SOFTWARE LLC portal - sessions, input validation and abuse controls.
//
// The portal never stores user passwords. MeshCentral is the single identity
// provider: the portal provisions the MeshCentral account at sign-up and then
// verifies credentials against MeshCentral on every login, so the portal
// password, the console password and the password used for native password
// resets are always the same secret.
//
// Sessions are stateless: an HMAC-SHA256 signed cookie carrying the portal user
// id and an absolute expiry. The signing key is SESSION_SECRET.

'use strict';

const crypto = require('crypto');
const { stmts, nowIso } = require('./authdb');
const mesh = require('./meshclient');

const SESSION_SECRET = process.env.SESSION_SECRET;
const COOKIE_NAME = 'ht_session';
const SESSION_TTL_HOURS = parseInt(process.env.SESSION_TTL_HOURS || '12', 10);
const MESH_URL = (process.env.MESH_URL || 'https://remote.exrmm.com').replace(/\/+$/, '');
// Address users are given for the console. MESH_URL can be internal or loopback.
const MESH_PUBLIC_URL = (process.env.MESH_PUBLIC_URL || 'https://remote.exrmm.com').replace(/\/+$/, '');
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || MESH_URL).replace(/\/+$/, '');
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@exrmm.com';
const SECURE_COOKIES = PUBLIC_BASE_URL.startsWith('https://');
// Portal administrators, comma separated. They see the admin Telegram feed
// settings in the dashboard and may configure notifications for all users.
// Defaults to the support mailbox so a single-operator deployment works
// without extra configuration.
const ADMIN_EMAILS = new Set(
  String(process.env.ADMIN_EMAILS || SUPPORT_EMAIL)
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
);

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('FATAL: SESSION_SECRET must be set to at least 32 characters (see .env)');
  process.exit(1);
}

// Promote the accounts listed in ADMIN_EMAILS to the database role once, so the
// operator dashboard can list administrators without reading the environment.
for (const email of ADMIN_EMAILS) {
  try {
    const row = stmts.getUserByEmail.get(email);
    if (row && row.role !== 'admin') stmts.setUserRole.run('admin', nowIso(), row.id);
  } catch (err) {
    console.error('[auth] admin role sync failed for ' + email + ': ' + err.message);
  }
}

// ---------------------------------------------------------------
// Cookie signing
// ---------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function sign(value) {
  return b64url(crypto.createHmac('sha256', SESSION_SECRET).update(value).digest());
}

function issueSession(res, user) {
  const payload = JSON.stringify({ uid: user.id, exp: Date.now() + SESSION_TTL_HOURS * 3600 * 1000 });
  const encoded = b64url(payload);
  const token = encoded + '.' + sign(encoded);
  const attrs = [
    COOKIE_NAME + '=' + token,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + SESSION_TTL_HOURS * 3600,
  ];
  if (SECURE_COOKIES) attrs.push('Secure');
  res.append('Set-Cookie', attrs.join('; '));
}

function clearSession(res) {
  const attrs = [COOKIE_NAME + '=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (SECURE_COOKIES) attrs.push('Secure');
  res.append('Set-Cookie', attrs.join('; '));
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

function decodeSession(req) {
  const token = readCookie(req, COOKIE_NAME);
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return null;
  const encoded = token.slice(0, dot);
  const provided = token.slice(dot + 1);
  const expected = sign(encoded);
  if (provided.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) return null;
  let payload;
  try {
    payload = JSON.parse(fromB64url(encoded).toString('utf8'));
  } catch (err) {
    return null;
  }
  if (!payload || typeof payload.uid !== 'number' || typeof payload.exp !== 'number') return null;
  if (payload.exp <= Date.now()) return null;
  return payload;
}

// ---------------------------------------------------------------
// Request guards
// ---------------------------------------------------------------
function loadUser(req) {
  const payload = decodeSession(req);
  if (!payload) return null;
  return stmts.getUserById.get(payload.uid) || null;
}

function requireUser(req, res, next) {
  const user = loadUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Sign in to continue', code: 'unauthenticated' });
  }
  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'This account is suspended. Contact ' + SUPPORT_EMAIL, code: 'suspended' });
  }
  if (user.status === 'expired' || user.status === 'purged') {
    return res.status(403).json({
      error: 'Your access has ended. Contact ' + SUPPORT_EMAIL + ' to extend it.',
      code: 'trial_expired',
    });
  }
  // The sweep runs on an interval; check the window here as well so an account
  // cannot keep using a session between expiry and the next sweep.
  if (
    user.status === 'trial' &&
    user.trial_ends_at &&
    new Date(user.trial_ends_at).getTime() <= Date.now()
  ) {
    return res.status(403).json({
      error: 'Your access window has ended. Contact ' + SUPPORT_EMAIL + ' to extend it.',
      code: 'access_expired',
    });
  }
  req.portalUser = user;
  next();
}

// ---------------------------------------------------------------
// Public user representation
// ---------------------------------------------------------------
function hoursLeft(user) {
  if (!user.trial_ends_at) return 0;
  const ms = new Date(user.trial_ends_at).getTime() - Date.now();
  return ms <= 0 ? 0 : Math.round((ms / 3600000) * 100) / 100;
}

function isAdmin(user) {
  if (!user) return false;
  // A database role always wins, so the operator account keeps working even if
  // ADMIN_EMAILS is edited later; the env list is the bootstrap source.
  if (String(user.role || '').toLowerCase() === 'admin') return true;
  return !!user.email && ADMIN_EMAILS.has(String(user.email).toLowerCase());
}

function userPayload(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    status: user.status,
    plan: user.plan,
    email_verified: !!user.email_verified,
    trial_started_at: user.trial_started_at,
    trial_ends_at: user.trial_ends_at,
    purge_after: user.purge_after,
    trial_active: user.status === 'trial' && hoursLeft(user) > 0,
    hours_left: hoursLeft(user),
    created_at: user.created_at,
    console_url: MESH_PUBLIC_URL + '/',
    mc_url: MESH_PUBLIC_URL + '/',
    support_email: SUPPORT_EMAIL,
    role: isAdmin(user) ? 'admin' : 'user',
    is_admin: isAdmin(user),
  };
}

// ---------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------
const EMAIL_RE = /^[^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

const WEAK_PASSWORDS = new Set([
  'password', 'password1', 'password123', '1234567890', 'qwertyuiop', 'letmein123',
  'administrator', 'exagent', 'changeme123', 'welcome123', 'iloveyou123',
]);

function normaliseEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function validateSignup({ name, email, password, passwordConfirm }) {
  const cleanName = typeof name === 'string' ? name.trim().replace(/\s+/g, ' ') : '';
  const cleanEmail = normaliseEmail(email);

  if (cleanName.length < 2 || cleanName.length > 80) {
    return { error: 'Enter your full name (2-80 characters)' };
  }
  if (!cleanEmail) return { error: 'Email address is required' };
  if (cleanEmail.length > 254 || !EMAIL_RE.test(cleanEmail)) {
    return { error: 'Enter a valid email address' };
  }
  if (typeof password !== 'string' || typeof passwordConfirm !== 'string') {
    return { error: 'Password is required' };
  }
  if (password !== passwordConfirm) return { error: 'Passwords do not match', code: 'password_mismatch' };

  const pwError = validatePassword(password);
  if (pwError) return { error: pwError };

  return { name: cleanName, email: cleanEmail, password };
}

function validatePassword(password) {
  // A password pasted from a clipboard often carries a trailing space or tab.
  // It is stored exactly as sent, so the operator can never type it back in and
  // every sign-in fails with "Incorrect email address or password". Reject the
  // surrounding whitespace instead of silently trimming it, so the person who
  // sets the password knows exactly what the credential is.
  if (password !== password.trim()) {
    return 'Password cannot start or end with a space';
  }
  if (password.length < 10) return 'Password must be at least 10 characters';
  if (password.length > 200) return 'Password must be at most 200 characters';
  if (!/[a-zA-Z]/.test(password)) return 'Password must contain at least one letter';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number';
  if (WEAK_PASSWORDS.has(password.toLowerCase())) return 'That password is too common, choose another';
  return null;
}

/**
 * Validate the "request account access" form. No password fields: the server
 * generates a credential and emails it to the address, which is what proves
 * ownership of the mailbox.
 */
function validateAccessRequest({ name, email, company }) {
  const cleanName = typeof name === 'string' ? name.trim().replace(/\s+/g, ' ') : '';
  const cleanEmail = normaliseEmail(email);
  const cleanCompany = typeof company === 'string' ? company.trim().replace(/\s+/g, ' ').slice(0, 120) : '';

  if (cleanName.length < 2 || cleanName.length > 80) {
    return { error: 'Enter your full name (2-80 characters)' };
  }
  if (!cleanEmail) return { error: 'Email address is required' };
  if (cleanEmail.length > 254 || !EMAIL_RE.test(cleanEmail)) {
    return { error: 'Enter a valid email address' };
  }
  return { name: cleanName, email: cleanEmail, company: cleanCompany || null };
}

/**
 * Validate the "book a demo" form. Everything except name and email is
 * optional free text the owner reads when scheduling manually.
 */
function validateDemoRequest({ name, email, company, preferred, notes }) {
  const base = validateAccessRequest({ name, email, company });
  if (base.error) return base;
  const cleanPreferred =
    typeof preferred === 'string' ? preferred.trim().replace(/\s+/g, ' ').slice(0, 120) : '';
  const cleanNotes = typeof notes === 'string' ? notes.trim().slice(0, 1000) : '';
  return {
    name: base.name,
    email: base.email,
    company: base.company,
    preferred: cleanPreferred || null,
    notes: cleanNotes || null,
  };
}

/**
 * Generate a sign-in password for access-request sign-ups: 16 characters,
 * guaranteed upper + lower + digit + symbol, no spaces, and no visually
 * ambiguous characters (0/O, 1/l/I) since the password arrives by email.
 */
function generatePassword() {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*-+_';
  const all = upper + lower + digits + symbols;
  const pick = (set) => set[crypto.randomInt(set.length)];
  const chars = [pick(upper), pick(lower), pick(digits), pick(symbols)];
  while (chars.length < 16) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// ---------------------------------------------------------------
// Rate limiting (in-process, per IP + bucket)
// ---------------------------------------------------------------
const buckets = new Map();

function rateLimit(name, max, windowMs) {
  return function (req, res, next) {
    const key = name + ':' + (req.clientIp || req.ip || 'unknown');
    const now = Date.now();
    let entry = buckets.get(key);
    if (!entry || entry.reset <= now) {
      entry = { count: 0, reset: now + windowMs };
      buckets.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      const retryAfter = Math.ceil((entry.reset - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({
        error: 'Too many attempts. Try again in ' + Math.ceil(retryAfter / 60) + ' minute(s).',
        code: 'rate_limited',
      });
    }
    next();
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of buckets) {
    if (entry.reset <= now) buckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

// ---------------------------------------------------------------
// Failed-verification counter (per account)
// ---------------------------------------------------------------
// MeshCentral throttles invalid logins itself (settings.maxinvalidlogin) and
// its default filter blocks the whole client IP range once enough bad logins
// accumulate. Every portal login reaches MeshCentral from the same backend
// address, so an attacker could use the portal to trip that filter and lock the
// entire platform out. The counter below stops the portal from ever feeding
// MeshCentral enough failures to trip it, and only counts rejected
// verifications - successful sign-ins are never affected.
const verifyFailures = new Map();

function verificationBlocked(name, key, max, windowMs) {
  const k = name + ':' + String(key || '').toLowerCase();
  const entry = verifyFailures.get(k);
  if (!entry || entry.reset <= Date.now()) return { blocked: false, retryAfter: 0 };
  if (entry.count < max) return { blocked: false, retryAfter: 0 };
  return { blocked: true, retryAfter: Math.ceil((entry.reset - Date.now()) / 1000) };
}

function noteVerificationFailure(name, key, max, windowMs) {
  const k = name + ':' + String(key || '').toLowerCase();
  const now = Date.now();
  let entry = verifyFailures.get(k);
  if (!entry || entry.reset <= now) entry = { count: 0, reset: now + windowMs };
  entry.count += 1;
  verifyFailures.set(k, entry);
  return entry.count;
}

function clearVerificationFailures(name, key) {
  verifyFailures.delete(name + ':' + String(key || '').toLowerCase());
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of verifyFailures) {
    if (entry.reset <= now) verifyFailures.delete(key);
  }
}, 5 * 60 * 1000).unref();

// ---------------------------------------------------------------
// MeshCentral credential check
// ---------------------------------------------------------------
/**
 * Prove an email/password pair against MeshCentral.
 *
 * A returned cookie is NOT proof of authentication: MeshCentral answers HTTP
 * 200 with an xid cookie even for rejected logins. mesh.login() therefore only
 * resolves for a session that actually carries a MeshCentral user id, and
 * rejects everything else with err.code = 'not_authenticated'.
 */
async function verifyMeshCentralCredentials(email, password) {
  try {
    const result = await mesh.login(MESH_URL, email, password);
    return { ok: true, cookie: result.cookie, userid: result.userid };
  } catch (err) {
    if (err.code === 'not_authenticated') return { ok: false, error: 'MeshCentral rejected those credentials' };
    return { ok: false, error: err.message, unavailable: true };
  }
}

module.exports = {
  COOKIE_NAME,
  SESSION_TTL_HOURS,
  PUBLIC_BASE_URL,
  MESH_URL,
  MESH_PUBLIC_URL,
  SUPPORT_EMAIL,
  ADMIN_EMAILS,
  isAdmin,
  issueSession,
  clearSession,
  loadUser,
  requireUser,
  requireUserIfPresent: loadUser,
  userPayload,
  hoursLeft,
  validateSignup,
  validateAccessRequest,
  validateDemoRequest,
  validatePassword,
  generatePassword,
  normaliseEmail,
  rateLimit,
  verificationBlocked,
  noteVerificationFailure,
  clearVerificationFailures,
  verifyMeshCentralCredentials,
};
