// EXagent portal - API server.
//
// MeshCentral uses a self-signed certificate internally, so SSL
// verification is disabled for all outbound calls to it (per deployment
// requirement). This MUST happen before any network module loads.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '..', '..', '.env') });

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

const mesh = require('./meshclient');
const provision = require('./provision');
const auth = require('./auth');
const trial = require('./trial');
const account = require('./account');
const mail = require('./mail');
const { buildInstaller, INSTALLERS_DIR } = require('./builder');
const { buildMsi, discardMsi } = require('./msi');
const { getSilentWrapper, WINDOWS_AGENT_IDS, BACKGROUND_ONLY_FLAGS } = require('./silentagent');
const telegram = require('./telegram');
const users = require('./users');
const { db, stmts, dbPath } = require('./db');
const { stmts: portalStmts, nowIso } = require('./authdb');

const PORT = parseInt(process.env.PORT || '8090', 10);
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const MESH_URL = process.env.MESH_URL || 'https://remote.exrmm.com';
// Public address of the MeshCentral console. MESH_URL may be an internal or
// loopback endpoint; this one is what users and installed agents are told.
const MESH_PUBLIC_URL = (process.env.MESH_PUBLIC_URL || 'https://remote.exrmm.com').replace(/\/+$/, '');
const MESH_USER = process.env.MESH_USER;
const MESH_PASS = process.env.MESH_PASS;
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || MESH_URL).replace(/\/+$/, '');
// Agent downloads are served by the MeshCentral/console host, the dashboard by
// the portal host. Both are the same backend behind different nginx vhosts.
const AGENT_BASE_URL = (process.env.AGENT_BASE_URL || PUBLIC_BASE_URL).replace(/\/+$/, '');
// Apex marketing site and the dashboard origin it hands off to. The apex page
// posts its sign-in form to APP_URL, which is why both are explicit.
const LANDING_URL = (process.env.LANDING_URL || 'https://exrmm.com').replace(/\/+$/, '');
const APP_URL = (process.env.APP_URL || PUBLIC_BASE_URL).replace(/\/+$/, '');
const FRONTEND_DIST = path.join(__dirname, '..', '..', 'frontend', 'dist');

if (!ADMIN_API_KEY) {
  console.error('FATAL: ADMIN_API_KEY is not set (see .env)');
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
// Behind the nginx vhost, so req.ip is the real client address (used by the
// rate limiter). Only loopback and private ranges are trusted as proxies.
app.set('trust proxy', 'loopback, linklocal, uniquelocal');
app.use(express.json({ limit: '1mb' }));

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function requireAdmin(req, res, next) {
  const key = req.get('X-Admin-Key');
  if (!key || !crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_API_KEY))) {
    return res.status(401).json({ error: 'Invalid or missing X-Admin-Key' });
  }
  next();
}

function downloadUrlFor(token) {
  return PUBLIC_BASE_URL + '/api/installers/' + encodeURIComponent(token) + '/download';
}

// MSI files get their own content type so a browser / deployment tool saves
// them with the right handler instead of treating them as an .exe.
function contentTypeFor(format) {
  return format === 'msi' ? 'application/x-msi' : 'application/vnd.microsoft.portable-executable';
}

function installerDescriptor(row) {
  return {
    token: row.token,
    filename: row.filename,
    format: row.format || 'exe',
    size: row.size,
    sha256: row.sha256,
    downloads: row.downloads,
    created_at: row.installer_created_at || row.created_at,
    download_url: downloadUrlFor(row.token),
  };
}

function rowToClient(row, installers) {
  const rows = Array.isArray(installers) && installers.length ? installers : stmts.listInstallersForClient.all(row.id);
  const list = rows.map(installerDescriptor);
  const exe = list.find((i) => i.format === 'exe') || list[0] || null;
  return {
    id: row.id,
    name: row.name,
    meshid: row.meshid,
    created_at: row.created_at,
    // Unchanged historical shape: the .exe installer this client was created
    // with. `installers` below lists every format available for the client.
    installer: exe,
    installers: list,
  };
}

// ---------------------------------------------------------------
// Public API
// ---------------------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'exagent-portal',
    db: dbPath,
    meshcentral: MESH_URL,
    time: new Date().toISOString(),
  });
});

// Installer info for the public download page (token IS the credential).
app.get('/api/installers/:token', (req, res) => {
  const row = stmts.getInstallerByToken.get(req.params.token);
  if (!row) return res.status(404).json({ error: 'Unknown download token' });
  res.json({
    client_name: row.client_name,
    filename: row.filename,
    format: row.format || 'exe',
    size: row.size,
    created_at: row.created_at,
    download_url: downloadUrlFor(row.token),
  });
});

// The actual installer download.
app.get('/api/installers/:token/download', (req, res) => {
  const row = stmts.getInstallerByToken.get(req.params.token);
  if (!row) return res.status(404).json({ error: 'Unknown download token' });
  if (!fs.existsSync(row.path)) return res.status(410).json({ error: 'Installer file no longer available' });
  stmts.bumpDownloads.run(row.id);
  res.setHeader('Content-Type', contentTypeFor(row.format));
  res.setHeader('Content-Disposition', 'attachment; filename="' + row.filename + '"');
  fs.createReadStream(row.path).pipe(res);
});

// ---------------------------------------------------------------
// Single-click silent agent download (Windows "Background only").
//
// The public edge rewrites /meshagents?id=<3|4|43>&installflags=2 here. The
// MeshCentral agent that the server would normally hand out always opens its
// install dialog when double-clicked - InstallFlags=2 only hides the Connect
// button inside that dialog - so we answer with an NSIS wrapper around the same
// agent that elevates once (UAC) and then runs it with -fullinstall.
//
// installflags=0 (Background & interactive) and installflags=1 (Interactive
// only) are deliberately NOT handled: those keep MeshCentral's native agent
// and its dialog.
app.get('/api/silent-agent', async (req, res) => {
  const agentId = String(req.query.id || '');
  const meshid = typeof req.query.meshid === 'string' ? req.query.meshid : '';
  const installFlags = req.query.installflags == null ? BACKGROUND_ONLY_FLAGS : String(req.query.installflags);

  if (!WINDOWS_AGENT_IDS.has(agentId)) {
    return res.status(400).json({ error: 'id must be one of 3 (x86-32), 4 (x64), 43 (ARM64)' });
  }
  if (!meshid) return res.status(400).json({ error: 'meshid is required' });
  if (installFlags !== BACKGROUND_ONLY_FLAGS) {
    return res.status(400).json({ error: 'Only installflags=2 (Background only) is served by this endpoint' });
  }

  try {
    const built = await getSilentWrapper({
      agentId,
      meshid,
      installFlags,
      key: typeof req.query.key === 'string' ? req.query.key : undefined,
    });
    if (!fs.existsSync(built.path)) {
      return res.status(410).json({ error: 'Silent wrapper no longer available' });
    }
    console.log(
      '[silent-agent] ' +
        (built.cached ? 'cache hit' : 'built') +
        ' id=' + agentId + ' installflags=' + installFlags +
        ' -> ' + built.filename + ' (' + built.size + ' bytes)'
    );
    res.setHeader('Content-Type', 'application/vnd.microsoft.portable-executable');
    res.setHeader('Content-Disposition', 'attachment; filename="' + built.filename.replace(/"/g, '') + '"');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Silent-Wrapper-Sha256', built.sha256);
    fs.createReadStream(built.path).pipe(res);
  } catch (err) {
    console.error('[silent-agent] failed:', err.message);
    res.status(err.statusCode || 500).json({
      error: err.message,
      build_output: err.buildOutput || undefined,
    });
  }
});

// ---------------------------------------------------------------
// Admin API (X-Admin-Key protected)
// ---------------------------------------------------------------
app.get('/api/clients', requireAdmin, (req, res) => {
  // Wrapped, not passed by reference: Array.map would hand rowToClient the
  // element index as its second argument.
  res.json({ clients: stmts.listClients.all().map((row) => rowToClient(row)) });
});

app.post('/api/clients', requireAdmin, async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (!name || name.length > 128) {
    return res.status(400).json({ error: 'Client name is required (1-128 characters)' });
  }

  try {
    let client = stmts.getClientByName.get(name);
    if (!client) {
      const group = await mesh.createDeviceGroup(MESH_URL, MESH_USER, MESH_PASS, name, 'EX SOFTWARE LLC client device group');
      const info = stmts.insertClient.run(name, group.meshid);
      client = stmts.getClientById.get(info.lastInsertRowid);
    }

    const built = await buildInstaller({
      meshUrl: MESH_URL,
      publicUrl: MESH_PUBLIC_URL,
      clientName: client.name,
      meshid: client.meshid,
    });
    const variants = [{ format: 'exe', built }];

    // Same agent, packaged as an MSI for central deployment (msiexec /qn). A
    // wixl problem must not fail the whole provisioning call: the .exe is
    // already produced, so the failure is reported as msi_error instead.
    let msiError = null;
    try {
      variants.push({
        format: 'msi',
        built: await buildMsi({
          meshUrl: MESH_URL,
          publicUrl: MESH_PUBLIC_URL,
          clientName: client.name,
          meshid: client.meshid,
        }),
      });
    } catch (err) {
      msiError = err.message;
      console.error('[installer] MSI build failed for client "' + client.name + '": ' + err.message);
    }

    // One download token per format, so either installer can be handed out
    // individually through /api/installers/<token>.
    const installers = [];
    for (const variant of variants) {
      const token = crypto.randomUUID(); // UUID v4 download token
      stmts.insertInstallerWithFormat.run(
        client.id, token, variant.built.filename, variant.built.path, variant.built.size, variant.built.sha256, variant.format
      );
      installers.push(stmts.getInstallerByToken.get(token));
      console.log('[installer] ' + variant.format + ' built for client "' + client.name + '" -> ' + variant.built.path +
        ' (' + variant.built.size + ' bytes)' + (variant.built.cached ? ' [cached]' : ''));
    }

    const row = stmts.getClientById.get(client.id);
    res.status(201).json({
      client: rowToClient(row, installers),
      build_log_tail: built.buildLog.split('\n').slice(-3).join('\n'),
      msi_error: msiError || undefined,
    });
  } catch (err) {
    console.error('[clients] failed:', err.message);
    res.status(500).json({ error: err.message, build_output: err.buildOutput || undefined });
  }
});

app.delete('/api/clients/:id', requireAdmin, async (req, res) => {
  const client = stmts.getClientById.get(req.params.id);
  if (!client) return res.status(404).json({ error: 'Unknown client' });

  let meshDeleted = false;
  try {
    await mesh.deleteDeviceGroup(MESH_URL, MESH_USER, MESH_PASS, client.meshid);
    meshDeleted = true;
  } catch (err) {
    console.error('[clients] MeshCentral group delete failed:', err.message);
  }

  const dirName = require('./builder').safeDirName(client.name);
  fs.rmSync(path.join(INSTALLERS_DIR, dirName), { recursive: true, force: true });
  stmts.deleteInstallersForClient.run(client.id);
  stmts.deleteClient.run(client.id);
  res.json({ deleted: client.name, mesh_deleted: meshDeleted });
});

// ---------------------------------------------------------------
// Self-service portal API (/api/portal/*)
//
// One account per email address. MeshCentral remains the identity provider:
// the portal never stores passwords, it verifies them against MeshCentral and
// keeps only a signed session cookie.
// ---------------------------------------------------------------
function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.ip || null;
}

function fail(res, err, fallbackStatus) {
  const status = err.statusCode || fallbackStatus || 400;
  res.status(status).json({ error: err.message, code: err.code || undefined });
}

// Every credential check runs against MeshCentral from this single host, and
// MeshCentral throttles invalid logins as a whole (by client IP range by
// default). The portal therefore stops sending rejected verifications for one
// account well before MeshCentral's own threshold, so an attacker cannot use
// the portal to lock out the platform. Only rejected verifications count, so a
// user signing in normally is never affected.
const VERIFY_FAIL_MAX = 5;
const VERIFY_FAIL_WINDOW_MS = 15 * 60 * 1000;

function accountVerifyThrottled(res, user, bucket) {
  const state = auth.verificationBlocked(bucket, user.id, VERIFY_FAIL_MAX, VERIFY_FAIL_WINDOW_MS);
  if (!state.blocked) return false;
  res.status(429).json({
    error: 'Too many failed attempts for this account. Try again in ' + Math.ceil(state.retryAfter / 60) + ' minute(s).',
    code: 'account_throttled',
  });
  return true;
}

function ownedGroup(user, id) {
  const row = portalStmts.getMeshById.get(id);
  if (!row || row.user_id !== user.id) return null;
  return row;
}

function agentLinks(meshid, groupId) {
  const base = AGENT_BASE_URL;
  const q = '&meshid=' + encodeURIComponent(meshid);
  return {
    meshid,
    // Windows MSI built by this portal for the same agent, installable per
    // machine and deployable unattended (`msiexec /i exagent-setup.msi /qn`).
    // The route is behind the portal session, and that cookie is host-only for
    // the dashboard host, so this one link must not use the agent base URL: the
    // dashboard also re-bases it onto whichever host served the page.
    msi: groupId
      ? { x64: PUBLIC_BASE_URL + '/api/portal/groups/' + encodeURIComponent(groupId) + '/agent.msi' }
      : null,
    // One-click installers (NSIS, elevate once). The x64 package is built by
    // this portal from the group's current name, so the installed application
    // always carries the device-group name. Like the MSI it is served behind
    // the portal session, so it uses the portal origin, not the agent origin.
    silent: {
      x64: groupId
        ? PUBLIC_BASE_URL + '/api/portal/groups/' + encodeURIComponent(groupId) + '/agent.exe'
        : base + '/api/silent-agent?id=4&installflags=2' + q,
      x86: base + '/api/silent-agent?id=3&installflags=2' + q,
      arm64: base + '/api/silent-agent?id=43&installflags=2' + q,
    },
    // Stock MeshCentral agents (interactive install dialog).
    native: {
      x64: base + '/meshagents?id=4&installflags=2' + q,
      x86: base + '/meshagents?id=3&installflags=2' + q,
      arm64: base + '/meshagents?id=43&installflags=2' + q,
    },
  };
}

async function groupsPayload(user, devices) {
  const rows = portalStmts.listMeshesForUser.all(user.id);
  const counts = new Map();
  for (const d of devices) counts.set(d.group_id, (counts.get(d.group_id) || 0) + (d.online ? 1 : 0));
  return rows.map((r) => ({
    id: r.id,
    meshid: r.meshid,
    name: r.name,
    created_at: r.created_at,
    devices_online: counts.get(r.meshid) || 0,
  }));
}

function devicesForUser(user) {
  if (!user.mc_userid) return Promise.resolve([]);
  return provision.listDevicesForUser(user.mc_userid).catch((err) => {
    console.error('[portal] device list failed for ' + user.mc_userid + ': ' + err.message);
    return [];
  });
}

// Admin-only gate for the platform-wide notification feed.
function requirePortalAdmin(req, res, next) {
  if (!auth.isAdmin(req.portalUser)) {
    return res.status(403).json({ error: 'Administrator access required', code: 'forbidden' });
  }
  next();
}

function requireActiveTrial(req, res, next) {
  const user = req.portalUser;
  if (user.status === 'trial' && auth.hoursLeft(user) <= 0) {
    trial.sweep().catch(() => {});
    return res.status(403).json({
      error: 'Your trial has ended. Contact ' + auth.SUPPORT_EMAIL + ' for continuing access.',
      code: 'trial_expired',
    });
  }
  next();
}

// ---- public: marketing site config ----

// Self-serve registration is closed: the public signup page points visitors at
// Telegram and accounts are provisioned manually. SIGNUP_OPEN=true in .env
// reopens /api/portal/signup and /api/portal/request-access.
const SIGNUP_OPEN = (process.env.SIGNUP_OPEN || 'false').toLowerCase() === 'true';

app.get('/api/portal/config', (req, res) => {
  res.json({
    product: 'EXagent',
    trial_hours: trial.TRIAL_HOURS,
    warn_hours: trial.WARN_HOURS,
    purge_after_start_hours: trial.PURGE_AFTER_START_HOURS,
    console_url: auth.MESH_PUBLIC_URL + '/',
    portal_url: PUBLIC_BASE_URL + '/',
    support_email: auth.SUPPORT_EMAIL,
    signup_open: SIGNUP_OPEN,
    // Payment links are configured in .env once the card / crypto accounts
    // exist; the site only renders a button for a method that has a link.
    payment: {
      card_url: process.env.PAYMENT_CARD_URL || '',
      crypto_url: process.env.PAYMENT_CRYPTO_URL || '',
    },
  });
});

// ---- sign-up ----
app.post('/api/portal/signup', auth.rateLimit('signup', 8, 60 * 60 * 1000), async (req, res) => {
  if (!SIGNUP_OPEN) {
    return res.status(403).json({
      error: 'Registration is currently closed. Contact us on Telegram to get access.',
      code: 'signup_closed',
    });
  }
  const body = req.body || {};
  const check = auth.validateSignup({
    name: body.name,
    email: body.email,
    password: body.password,
    passwordConfirm: body.password_confirm != null ? body.password_confirm : body.passwordConfirm,
  });
  if (check.error) return res.status(400).json({ error: check.error, code: check.code || undefined });

  try {
    const { user, groupWarning } = await trial.startTrial({
      name: check.name,
      email: check.email,
      password: check.password,
      ip: clientIp(req),
    });
    auth.issueSession(res, user);
    telegram.notifyAdminUserEvent('signup', { email: user.email, name: user.name, ip: clientIp(req) });
    res.status(201).json({
      user: auth.userPayload(user),
      groups: [],
      confirmation_email_sent: true,
      warning: groupWarning || undefined,
    });
  } catch (err) {
    if (/already exists/i.test(err.message) || err.code === 'account_exists') {
      return res.status(409).json({ error: err.message, code: 'account_exists' });
    }
    console.error('[portal] signup failed for ' + check.email + ': ' + err.message);
    fail(res, err, 502);
  }
});

// ---- request access (credentials are emailed; no password chosen on the form) ----
const DEMO_NOTIFY_EMAIL = process.env.DEMO_NOTIFY_EMAIL || process.env.SMTP_USER || auth.SUPPORT_EMAIL;

app.post('/api/portal/request-access', auth.rateLimit('request-access', 5, 60 * 60 * 1000), async (req, res) => {
  if (!SIGNUP_OPEN) {
    return res.status(403).json({
      error: 'Registration is currently closed. Contact us on Telegram to get access.',
      code: 'signup_closed',
    });
  }
  const body = req.body || {};
  const check = auth.validateAccessRequest(body);
  if (check.error) return res.status(400).json({ error: check.error, code: check.code || undefined });

  const OK_MESSAGE =
    'Request received. If access can be granted for this address, your sign-in credentials will arrive by email within a few minutes.';

  try {
    // Never reveal whether an account already exists: duplicate and fresh
    // requests get the same generic answer, so the endpoint cannot be used to
    // enumerate registered addresses or re-send credentials to them.
    const existing = portalStmts.getUserByEmail.get(check.email);
    if (!existing && !(await provision.getAccount(provision.useridFor(check.email)))) {
      const password = auth.generatePassword();
      const { user } = await trial.startTrial({
        name: check.name,
        email: check.email,
        password,
        ip: clientIp(req),
        flow: 'credentials',
      });
      trial.logEvent(user.id, 'access_granted', 'credentials emailed', clientIp(req));
      telegram.notifyAdminUserEvent('access_granted', { email: user.email, name: user.name, ip: clientIp(req) });
    } else {
      trial.logEvent(existing ? existing.id : null, 'access_request_duplicate', check.email, clientIp(req));
    }
    return res.status(202).json({ ok: true, message: OK_MESSAGE });
  } catch (err) {
    console.error('[portal] access request failed for ' + check.email + ': ' + err.message);
    return fail(res, err, 502);
  }
});

// ---- book a demo (scheduling happens manually by email afterwards) ----
app.post('/api/portal/book-demo', auth.rateLimit('book-demo', 5, 60 * 60 * 1000), async (req, res) => {
  const body = req.body || {};
  const check = auth.validateDemoRequest(body);
  if (check.error) return res.status(400).json({ error: check.error, code: check.code || undefined });

  const createdAt = nowIso();
  let rowId = null;
  try {
    const info = portalStmts.insertDemoRequest.run({
      name: check.name,
      email: check.email,
      company: check.company,
      preferred: check.preferred,
      notes: check.notes,
      ip: clientIp(req),
      created_at: createdAt,
    });
    rowId = info.lastInsertRowid;
  } catch (err) {
    console.error('[portal] demo request insert failed: ' + err.message);
  }
  trial.logEvent(null, 'demo_requested', check.email + (check.company ? ' (' + check.company + ')' : ''), clientIp(req));

  // Mail failures never fail the request: the row is stored either way.
  const [toRequester, toOwner] = await Promise.allSettled([
    mail.sendDemoRequested({ to: check.email, name: check.name }),
    mail.sendDemoNotify({
      to: DEMO_NOTIFY_EMAIL,
      name: check.name,
      email: check.email,
      company: check.company,
      preferred: check.preferred,
      notes: check.notes,
      requestedAt: createdAt,
    }),
  ]);
  const ownerSent = toOwner.status === 'fulfilled' && toOwner.value.sent;
  if (!ownerSent) {
    console.error('[portal] demo notify email not delivered (request stored as id ' + rowId + ')');
  }

  return res.status(202).json({
    ok: true,
    message:
      'Demo request received. We will email you shortly to schedule a time that works for you.',
  });
});

// ---- session ----
// One sign-in routine shared by the JSON API and the marketing site form POST.
// It returns a result object; the session cookie is attached to `res` only when
// every account gate passes.
async function signInAccount(req, res, email, password) {
  if (!email || !password) return { ok: false, status: 400, body: { error: 'Email address and password are required' } };

  const user = portalStmts.getUserByEmail.get(email);
  const throttle = auth.verificationBlocked('login_account', email, VERIFY_FAIL_MAX, VERIFY_FAIL_WINDOW_MS);
  if (throttle.blocked) {
    trial.logEvent(user ? user.id : null, 'login_throttled', email, clientIp(req));
    return {
      ok: false,
      status: 429,
      body: {
        error: 'Too many failed sign-in attempts for this account. Try again in ' + Math.ceil(throttle.retryAfter / 60) + ' minute(s).',
        code: 'account_throttled',
      },
    };
  }

  let authed;
  try {
    authed = await provision.verifyCredentials(email, password);
  } catch (err) {
    console.error('[portal] credential verification failed: ' + err.message);
    return { ok: false, status: err.statusCode || 503, body: { error: err.message, code: err.code || undefined } };
  }
  if (!authed) {
    auth.noteVerificationFailure('login_account', email, VERIFY_FAIL_MAX, VERIFY_FAIL_WINDOW_MS);
    trial.logEvent(user ? user.id : null, 'login_failed', email, clientIp(req));
    return { ok: false, status: 401, body: { error: 'Incorrect email address or password', code: 'bad_credentials' } };
  }
  auth.clearVerificationFailures('login_account', email);

  if (!user) {
    return {
      ok: false,
      status: 403,
      body: {
        error: 'This account is managed by an administrator and has no self-service dashboard. Contact ' + auth.SUPPORT_EMAIL + '.',
        code: 'managed_account',
      },
    };
  }
  if (user.status === 'suspended') {
    return { ok: false, status: 403, body: { error: 'This account is suspended. Contact ' + auth.SUPPORT_EMAIL, code: 'suspended' } };
  }
  if (user.status === 'expired' || user.status === 'purged' || (user.status === 'trial' && auth.hoursLeft(user) <= 0)) {
    trial.sweep().catch(() => {});
    return {
      ok: false,
      status: 403,
      body: { error: 'Your trial has ended. Contact ' + auth.SUPPORT_EMAIL + ' for continuing access.', code: 'trial_expired' },
    };
  }

  const now = nowIso();
  portalStmts.touchLogin.run(now, now, user.id);
  auth.issueSession(res, user);
  trial.logEvent(user.id, 'login', email, clientIp(req));
  telegram.notifyAdminUserEvent('login', { email: user.email, name: user.name, ip: clientIp(req) });
  return { ok: true, user };
}

app.post('/api/portal/login', auth.rateLimit('login', 20, 15 * 60 * 1000), async (req, res) => {
  const body = req.body || {};
  const email = auth.normaliseEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  const result = await signInAccount(req, res, email, password);
  if (!result.ok) return res.status(result.status).json(result.body);
  const user = result.user;
  res.json({
    user: auth.userPayload(portalStmts.getUserById.get(user.id)),
    groups: await groupsPayload(user, await devicesForUser(user)),
  });
});

// The apex marketing site (exrmm.com) runs on its own origin, so it cannot read
// a cookie set for app.exrmm.com from cross-origin fetch(). Its sign-in form is
// instead a plain top-level POST here: the session cookie is set first-party on
// the app origin, then the browser is redirected into the dashboard.
app.post(
  '/api/session/login',
  auth.rateLimit('login', 20, 15 * 60 * 1000),
  express.urlencoded({ extended: false }),
  async (req, res) => {
    const body = req.body || {};
    const email = auth.normaliseEmail(body.email);
    const password = typeof body.password === 'string' ? body.password : '';
    const result = await signInAccount(req, res, email, password);
    if (!result.ok) {
      const reason = (result.body && result.body.code) || 'signin_failed';
      return res.redirect(303, LANDING_URL + '/?error=' + encodeURIComponent(reason));
    }
    return res.redirect(303, APP_URL + '/dashboard');
  },
);

app.post('/api/portal/logout', (req, res) => {
  auth.clearSession(res);
  res.json({ ok: true });
});

app.get('/api/portal/me', auth.requireUser, async (req, res) => {
  const devices = await devicesForUser(req.portalUser);
  res.json({
    user: auth.userPayload(req.portalUser),
    groups: await groupsPayload(req.portalUser, devices),
    devices,
    console_url: auth.MESH_PUBLIC_URL + "/",
  });
});

// ---- device groups ----
app.get('/api/portal/groups', auth.requireUser, requireActiveTrial, async (req, res) => {
  res.json({ groups: await groupsPayload(req.portalUser, await devicesForUser(req.portalUser)) });
});

app.post('/api/portal/groups', auth.requireUser, requireActiveTrial, async (req, res) => {
  const name = typeof (req.body || {}).name === 'string' ? req.body.name.trim().replace(/\s+/g, ' ') : '';
  if (name.length < 2 || name.length > 64) {
    return res.status(400).json({ error: 'Device group name must be 2-64 characters' });
  }
  const existing = portalStmts.countMeshesForUser.get(req.portalUser.id).n;
  if (existing >= 10) return res.status(429).json({ error: 'Trial accounts are limited to 10 device groups', code: 'group_limit' });

  try {
    const row = await trial.createGroupForUser(req.portalUser, name);
    trial.logEvent(req.portalUser.id, 'group_create', name, clientIp(req));
    res.status(201).json({ group: { id: row.id, meshid: row.meshid, name: row.name, created_at: row.created_at, devices_online: 0 } });
  } catch (err) {
    console.error('[portal] group create failed: ' + err.message);
    fail(res, err, 502);
  }
});

app.patch('/api/portal/groups/:id', auth.requireUser, requireActiveTrial, async (req, res) => {
  const row = ownedGroup(req.portalUser, req.params.id);
  if (!row) return res.status(404).json({ error: 'Unknown device group' });
  const name = typeof (req.body || {}).name === 'string' ? req.body.name.trim().replace(/\s+/g, ' ') : '';
  if (name.length < 2 || name.length > 64) return res.status(400).json({ error: 'Device group name must be 2-64 characters' });
  const oldName = row.name;

  try {
    await provision.renameDeviceGroup(row.meshid, name, 'EX SOFTWARE LLC device group');
    portalStmts.renameMesh.run(name, row.id);
    // Every name inside the MSI is derived from the group name, so the package
    // built for the old name must never be served again for this group.
    try {
      discardMsi(oldName);
    } catch (err) {
      console.error('[msi] could not drop stale package for "' + oldName + '": ' + err.message);
    }
    trial.logEvent(req.portalUser.id, 'group_rename', row.name + ' -> ' + name, clientIp(req));
    res.json({ group: { id: row.id, meshid: row.meshid, name, created_at: row.created_at, devices_online: 0 } });
  } catch (err) {
    console.error('[portal] group rename failed: ' + err.message);
    fail(res, err, 502);
  }
});

app.delete('/api/portal/groups/:id', auth.requireUser, async (req, res) => {
  const row = ownedGroup(req.portalUser, req.params.id);
  if (!row) return res.status(404).json({ error: 'Unknown device group' });
  await trial.deleteGroupForUser(req.portalUser, row);
  res.json({ deleted: row.name });
});

app.get('/api/portal/groups/:id/devices', auth.requireUser, async (req, res) => {
  const row = ownedGroup(req.portalUser, req.params.id);
  if (!row) return res.status(404).json({ error: 'Unknown device group' });
  const devices = (await devicesForUser(req.portalUser)).filter((d) => d.group_id === row.meshid);
  res.json({ group: { id: row.id, meshid: row.meshid, name: row.name }, devices });
});

app.get('/api/portal/groups/:id/agent', auth.requireUser, requireActiveTrial, (req, res) => {
  const row = ownedGroup(req.portalUser, req.params.id);
  if (!row) return res.status(404).json({ error: 'Unknown device group' });
  res.json({ group: { id: row.id, meshid: row.meshid, name: row.name }, agent: agentLinks(row.meshid, row.id) });
});

// Windows MSI for the same group agent. The MSI is built on demand (embedded
// agent is cached per mesh id) and then cached on disk next to the .exe.
app.get('/api/portal/groups/:id/agent.msi', auth.requireUser, requireActiveTrial, async (req, res) => {
  const row = ownedGroup(req.portalUser, req.params.id);
  if (!row) return res.status(404).json({ error: 'Unknown device group' });

  try {
    const built = await buildMsi({
      meshUrl: MESH_URL,
      publicUrl: MESH_PUBLIC_URL,
      clientName: row.name,
      meshid: row.meshid,
    });
    trial.logEvent(req.portalUser.id, 'agent_msi', row.name, clientIp(req));
    console.log('[msi] ' + (built.cached ? 'cached' : 'built') + ' for group "' + row.name + '" -> ' + built.path +
      ' (' + built.size + ' bytes)');
    res.setHeader('Content-Type', contentTypeFor('msi'));
    res.setHeader('Content-Length', String(built.size));
    res.setHeader('Content-Disposition', 'attachment; filename="' + built.filename + '"');
    fs.createReadStream(built.path).pipe(res);
  } catch (err) {
    console.error('[msi] build failed for group "' + row.name + '": ' + err.message);
    res.status(500).json({ error: 'Could not build the MSI installer: ' + err.message });
  }
});

// Windows .exe installer for the same group agent (NSIS, silent, one UAC
// prompt). Built on demand from the group's current name so the installed
// application always carries the device-group name, no matter what the saved
// file is called and no matter what the group was called before a rename.
app.get('/api/portal/groups/:id/agent.exe', auth.requireUser, requireActiveTrial, async (req, res) => {
  const row = ownedGroup(req.portalUser, req.params.id);
  if (!row) return res.status(404).json({ error: 'Unknown device group' });

  try {
    const built = await buildInstaller({
      meshUrl: MESH_URL,
      publicUrl: MESH_PUBLIC_URL,
      clientName: row.name,
      meshid: row.meshid,
    });
    trial.logEvent(req.portalUser.id, 'agent_exe', row.name, clientIp(req));
    console.log('[exe] built for group "' + row.name + '" -> ' + built.path + ' (' + built.size + ' bytes)');
    res.setHeader('Content-Type', contentTypeFor('exe'));
    res.setHeader('Content-Length', String(built.size));
    res.setHeader('Content-Disposition', 'attachment; filename="' + built.filename + '"');
    fs.createReadStream(built.path).pipe(res);
  } catch (err) {
    console.error('[exe] build failed for group "' + row.name + '": ' + err.message);
    res.status(500).json({ error: 'Could not build the .exe installer: ' + err.message });
  }
});

app.get('/api/portal/devices', auth.requireUser, async (req, res) => {
  res.json({ devices: await devicesForUser(req.portalUser) });
});

app.get('/api/portal/events', auth.requireUser, (req, res) => {
  res.json({
    events: portalStmts.listEventsForUser.all(req.portalUser.id).map((e) => ({
      kind: e.kind,
      detail: e.detail,
      created_at: e.created_at,
    })),
  });
});

// ---- account settings ----
app.post('/api/portal/account/name', auth.requireUser, requireActiveTrial, async (req, res) => {
  try {
    const result = await account.changeName(req.portalUser, (req.body || {}).name, clientIp(req));
    res.json({ user: auth.userPayload(result.user), console_updated: result.mcUpdated });
  } catch (err) {
    fail(res, err);
  }
});

app.post('/api/portal/account/password', auth.requireUser, requireActiveTrial, auth.rateLimit('pwchange', 10, 60 * 60 * 1000), async (req, res) => {
  const body = req.body || {};
  if (accountVerifyThrottled(res, req.portalUser, 'pwchange_account')) return;
  try {
    await account.changePassword(req.portalUser, body.current_password, body.new_password, clientIp(req));
    auth.clearVerificationFailures('pwchange_account', req.portalUser.id);
    res.json({ ok: true, must_sign_in_again: false });
  } catch (err) {
    if (err.code === 'bad_credentials') {
      auth.noteVerificationFailure('pwchange_account', req.portalUser.id, VERIFY_FAIL_MAX, VERIFY_FAIL_WINDOW_MS);
    }
    fail(res, err, 502);
  }
});

app.post('/api/portal/account/email', auth.requireUser, requireActiveTrial, auth.rateLimit('emailchange', 5, 60 * 60 * 1000), async (req, res) => {
  const body = req.body || {};
  if (accountVerifyThrottled(res, req.portalUser, 'emailchange_account')) return;
  try {
    const result = await account.changeEmail(req.portalUser, body.current_password, body.new_email, clientIp(req));
    auth.clearVerificationFailures('emailchange_account', req.portalUser.id);
    res.json({ user: auth.userPayload(result.user), groups_moved: result.groupsMoved, warnings: result.warnings });
  } catch (err) {
    if (err.code === 'bad_credentials') {
      auth.noteVerificationFailure('emailchange_account', req.portalUser.id, VERIFY_FAIL_MAX, VERIFY_FAIL_WINDOW_MS);
    }
    fail(res, err, 502);
  }
});

// ---- email confirmation + password reset (public) ----
app.post('/api/portal/verify', (req, res) => {
  const token = (req.body || {}).token;
  const user = trial.consumeToken(token, 'confirm');
  if (!user) return res.status(400).json({ error: 'That confirmation link is invalid or has expired.', code: 'bad_token' });
  portalStmts.markEmailVerified.run(nowIso(), user.id);
  trial.logEvent(user.id, 'email_verified', user.email, clientIp(req));
  res.json({ verified: true, user: auth.userPayload(portalStmts.getUserById.get(user.id)) });
});

app.post('/api/portal/forgot', auth.rateLimit('forgot', 6, 60 * 60 * 1000), async (req, res) => {
  const email = auth.normaliseEmail((req.body || {}).email);
  if (!email) return res.status(400).json({ error: 'Email address is required' });
  // Always the same answer: this endpoint must not reveal which addresses exist.
  await account.requestPasswordReset(email, clientIp(req));
  res.json({ ok: true, message: 'If an account exists for that address, a reset link is on its way.' });
});

app.post('/api/portal/reset', auth.rateLimit('reset', 12, 60 * 60 * 1000), async (req, res) => {
  const body = req.body || {};
  const confirm = body.password_confirm != null ? body.password_confirm : body.passwordConfirm;
  if (typeof body.password !== 'string' || body.password !== confirm) {
    return res.status(400).json({ error: 'Passwords do not match', code: 'password_mismatch' });
  }
  try {
    const result = await account.completePasswordReset(body.token, body.password, clientIp(req));
    res.json({ ok: true, user: auth.userPayload(result.user) });
  } catch (err) {
    fail(res, err, 502);
  }
});

// ---- admin: run the trial sweep on demand (support/testing) ----
app.post('/api/admin/trial-sweep', requireAdmin, async (req, res) => {
  try {
    res.json(await trial.sweep());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- admin: demo requests awaiting manual scheduling ----
app.get('/api/admin/demo-requests', requireAdmin, (req, res) => {
  res.json({ requests: portalStmts.listDemoRequests.all() });
});

app.patch('/api/admin/demo-requests/:id', requireAdmin, (req, res) => {
  const status = (req.body || {}).status;
  if (!['new', 'scheduled', 'done', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'status must be one of new|scheduled|done|closed' });
  }
  const info = portalStmts.setDemoRequestStatus.run(status, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Unknown demo request' });
  res.json({ ok: true, status });
});

// ---------------------------------------------------------------
// Telegram notifications - per user (optional)
// ---------------------------------------------------------------
app.get('/api/portal/telegram', auth.requireUser, (req, res) => {
  res.json({
    settings: telegram.publicSettings(req.portalUser.id),
    is_admin: auth.isAdmin(req.portalUser),
    poll_seconds: telegram.POLL_SECONDS,
  });
});

app.post('/api/portal/telegram', auth.requireUser, async (req, res) => {
  try {
    const settings = await telegram.saveSettings(req.portalUser.id, req.body || {});
    res.json({ settings });
  } catch (err) {
    fail(res, err, 502);
  }
});

app.delete('/api/portal/telegram', auth.requireUser, (req, res) => {
  res.json({ settings: telegram.deleteSettings(req.portalUser.id) });
});

app.post('/api/portal/telegram/enabled', auth.requireUser, (req, res) => {
  try {
    res.json({ settings: telegram.setEnabled(req.portalUser.id, !!(req.body || {}).enabled) });
  } catch (err) {
    fail(res, err, 404);
  }
});

// Telegram only reveals a chat id after the user has messaged the bot, so the
// UI asks them to press Start and then detects the chat for them.
app.post('/api/portal/telegram/detect', auth.requireUser, async (req, res) => {
  try {
    res.json(await telegram.detectChatForUser(req.portalUser.id, (req.body || {}).bot_token));
  } catch (err) {
    fail(res, err, 400);
  }
});

app.post(
  '/api/portal/telegram/test',
  auth.requireUser,
  auth.rateLimit('telegram-test', 6, 10 * 60 * 1000),
  async (req, res) => {
    try {
      res.json(await telegram.sendTest(req.portalUser.id));
    } catch (err) {
      fail(res, err, 502);
    }
  }
);

// ---------------------------------------------------------------
// Telegram notifications - platform admin feed
// ---------------------------------------------------------------
app.get('/api/portal/admin/telegram', auth.requireUser, requirePortalAdmin, (req, res) => {
  res.json({ settings: telegram.getAdminConfig() });
});

app.post('/api/portal/admin/telegram', auth.requireUser, requirePortalAdmin, async (req, res) => {
  try {
    res.json({ settings: await telegram.saveAdminConfig(req.body || {}) });
  } catch (err) {
    fail(res, err, 502);
  }
});

app.post('/api/portal/admin/telegram/detect', auth.requireUser, requirePortalAdmin, async (req, res) => {
  try {
    res.json(await telegram.detectChat((req.body || {}).bot_token));
  } catch (err) {
    fail(res, err, 400);
  }
});

app.delete('/api/portal/admin/telegram', auth.requireUser, requirePortalAdmin, (req, res) => {
  res.json({ settings: telegram.deleteAdminConfig() });
});

app.post(
  '/api/portal/admin/telegram/test',
  auth.requireUser,
  requirePortalAdmin,
  auth.rateLimit('telegram-admin-test', 6, 10 * 60 * 1000),
  async (req, res) => {
    try {
      res.json(await telegram.sendAdminTest());
    } catch (err) {
      fail(res, err, 502);
    }
  }
);

// Manual presence sweep - useful right after enabling notifications.
app.post('/api/portal/admin/telegram/poll', auth.requireUser, requirePortalAdmin, async (req, res) => {
  try {
    res.json(await telegram.pollOnce());
  } catch (err) {
    fail(res, err, 502);
  }
});

// ---------------------------------------------------------------
// Account management - owner only
//
// The operator creates client accounts here and hands over the credentials
// directly; each one is a plain console user with no administrator rights and
// no trial expiry. Every route below is gated by the signed-in session AND the
// administrator role, so a client account cannot reach another client's data.
// ---------------------------------------------------------------
app.get('/api/portal/admin/users', auth.requireUser, requirePortalAdmin, (req, res) => {
  res.json({ users: users.list({ search: req.query.q }) });
});

app.post(
  '/api/portal/admin/users',
  auth.requireUser,
  requirePortalAdmin,
  auth.rateLimit('admin-user-create', 30, 60 * 60 * 1000),
  async (req, res) => {
    try {
      const body = req.body || {};
      const result = await users.create({
        name: body.name,
        email: body.email,
        password: body.password,
        plan: body.plan,
        groups: body.groups,
        access: body.access,
        ip: clientIp(req),
      });
      res.status(201).json(result);
    } catch (err) {
      fail(res, err, 400);
    }
  }
);

app.post('/api/portal/admin/users/:id/password', auth.requireUser, requirePortalAdmin, async (req, res) => {
  try {
    res.json(await users.resetPassword(req.params.id, (req.body || {}).password, clientIp(req)));
  } catch (err) {
    fail(res, err, 400);
  }
});

app.patch('/api/portal/admin/users/:id', auth.requireUser, requirePortalAdmin, async (req, res) => {
  const body = req.body || {};
  try {
    if (typeof body.name === 'string' && body.name.trim()) {
      return res.json(await users.rename(req.params.id, body.name, clientIp(req)));
    }
    if (typeof body.status === 'string') {
      return res.json(await users.setStatus(req.params.id, body.status, clientIp(req)));
    }
    // Access window in hours or days: { access: { amount, unit } }.
    // { access: null } removes the limit again.
    if ('access' in body) {
      return res.json(await users.setAccess(req.params.id, body.access, clientIp(req)));
    }
    res.status(400).json({ error: 'Provide a name, a status or an access window to update' });
  } catch (err) {
    fail(res, err, 400);
  }
});

app.delete('/api/portal/admin/users/:id', auth.requireUser, requirePortalAdmin, async (req, res) => {
  try {
    res.json(await users.remove(req.params.id, clientIp(req)));
  } catch (err) {
    fail(res, err, 400);
  }
});

// ---------------------------------------------------------------
// Frontend (React SPA built to frontend/dist)
//
// app.exrmm.com serves the SPA from the SITE ROOT because its built
// assets are referenced root-relative (/assets/..., /favicon.ico). The
// /portal mount is kept as an alias for the console host.
// ---------------------------------------------------------------
if (fs.existsSync(FRONTEND_DIST)) {
  const spaIndex = path.join(FRONTEND_DIST, 'index.html');

  // Legacy alias, kept so remote.exrmm.com/portal still resolves.
  app.use('/portal', express.static(FRONTEND_DIST));
  app.get(/^\/portal(\/.*)?$/, (req, res) => {
    res.sendFile(spaIndex);
  });

  // Site root: hashed assets, images and the favicon set come off disk.
  app.use(express.static(FRONTEND_DIST));

  // Anything else that is not the API falls through to the SPA shell so
  // client-side routes (/login, /dashboard, ...) survive a hard refresh.
  app.get(/^\/(?!api\/).*/, (req, res) => {
    res.sendFile(spaIndex);
  });
}

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Trial lifecycle: warn at WARN_HOURS, block sign-in at TRIAL_HOURS, delete the
// workspace PURGE_AFTER_START_HOURS after the trial started.
trial.startSweeper();
// Device presence watcher: only polls accounts that opted in, plus every active
// account when the admin feed is enabled.
telegram.startWatcher();
trial
  .sweep()
  .then((s) => console.log('[trial] startup sweep warned=' + s.warned + ' expired=' + s.expired + ' purged=' + s.purged))
  .catch((err) => console.error('[trial] startup sweep failed: ' + err.message));

// Bind host: 127.0.0.1 behind an edge proxy, 0.0.0.0 for the standalone
// IP-only deployment where the portal is reached directly on its own port.
const BIND_HOST = process.env.BIND_HOST || '0.0.0.0';

const httpServer = app.listen(PORT, BIND_HOST, () => {
  console.log('EX SOFTWARE LLC portal backend listening on http://' + BIND_HOST + ':' + PORT);
  console.log('  MeshCentral: ' + MESH_URL);
  console.log('  DB:          ' + dbPath);
});

// Connection lifetime: Node closes idle keep-alive sockets after 5s, shorter
// than browsers keep them, so the next request on a reused socket can die with
// a transport error ("first click failed, second one worked"). Hold sockets far
// longer than any browser does; headersTimeout must stay above keepAliveTimeout.
httpServer.keepAliveTimeout = 65000;
httpServer.headersTimeout = 66000;
httpServer.requestTimeout = 300000;

