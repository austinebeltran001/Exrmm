// EX SOFTWARE LLC portal - administrator-provisioned client accounts.
//
// An administrator creates the account, chooses the sign-in password and hands
// those credentials over directly; nothing is emailed. The MeshCentral account
// stays the identity provider, so the password set here is also the password
// for the EXagent console at remote.exrmm.com, and it can be changed by the
// user later from the dashboard.
//
// Every account created here is a plain client account: role 'user' and no
// siteadmin bit at MeshCentral. An account has unlimited access unless the
// operator sets an access window in hours or days, which is enforced by the
// trial lifecycle (portal block + console lock, never auto-delete). Only the
// portal owner account (ADMIN_EMAILS / role 'admin') may call into this module.

'use strict';

const provision = require('./provision');
const auth = require('./auth');
const trial = require('./trial');
const { stmts, nowIso } = require('./authdb');

const DEFAULT_PLAN = 'standard';
const HOUR_MS = 60 * 60 * 1000;
const MAX_ACCESS_DAYS = 1825; // five years

function httpError(status, message, code) {
  const err = new Error(message);
  err.statusCode = status;
  if (code) err.code = code;
  return err;
}

function hoursLeft(row) {
  if (!row || !row.trial_ends_at) return 0;
  const ms = new Date(row.trial_ends_at).getTime() - Date.now();
  return ms <= 0 ? 0 : Math.round((ms / HOUR_MS) * 100) / 100;
}

/**
 * Normalise an operator-supplied access window.
 *
 * `null` clears the window (the account gets unlimited access again), otherwise
 * `{ amount, unit }` with unit 'hours' or 'days' is required. The result is
 * always expressed in hours so the caller does the arithmetic exactly once.
 */
function normaliseAccess(access) {
  if (access === null) return { clear: true };
  if (!access || typeof access !== 'object' || Array.isArray(access)) {
    return { error: 'Provide an access window as { amount, unit } or null to remove it' };
  }
  const unit = typeof access.unit === 'string' ? access.unit.trim().toLowerCase() : '';
  if (unit !== 'hours' && unit !== 'days') {
    return { error: 'The access unit must be hours or days' };
  }
  const amount = Number(access.amount);
  if (!Number.isInteger(amount) || amount < 1) {
    return { error: 'Enter a whole number of ' + unit + ' (1 or more)' };
  }
  const hours = unit === 'days' ? amount * 24 : amount;
  if (hours > MAX_ACCESS_DAYS * 24) {
    return { error: 'The longest access window is ' + MAX_ACCESS_DAYS + ' days' };
  }
  return { hours, amount, unit };
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    status: row.status,
    plan: row.plan,
    role: row.role === 'admin' ? 'admin' : 'user',
    is_admin: row.role === 'admin',
    group_count: Number(row.group_count || 0),
    access_started_at: row.trial_started_at || null,
    access_expires_at: row.trial_ends_at || null,
    hours_left: hoursLeft(row),
    email_verified: !!row.email_verified,
    last_login_at: row.last_login_at || null,
    created_at: row.created_at,
  };
}

function defaultGroupName(name) {
  const first = String(name || '').trim().split(/\s+/)[0];
  const base = first && first.length >= 2 ? first : 'Client';
  return base + "'s Devices";
}

/** Validate the operator-supplied fields for a new or updated account. */
function validateAccountInput({ name, email, password }, { passwordRequired = true } = {}) {
  const cleanName = typeof name === 'string' ? name.trim().replace(/\s+/g, ' ') : '';
  const cleanEmail = auth.normaliseEmail(email);

  if (cleanName.length < 2 || cleanName.length > 80) {
    return { error: 'Enter the account holder name (2-80 characters)' };
  }
  if (!cleanEmail) return { error: 'Email address is required' };
  if (cleanEmail.length > 254 || !/^[^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(cleanEmail)) {
    return { error: 'Enter a valid email address' };
  }
  if (passwordRequired || password) {
    if (typeof password !== 'string' || !password) return { error: 'A password is required' };
    const pwError = auth.validatePassword(password);
    if (pwError) return { error: pwError };
  }
  return { name: cleanName, email: cleanEmail, password };
}

/**
 * Single operator listing: every portal account, with role, status, plan and
 * device-group count. MeshCentral is not queried here so the page stays fast
 * even when the console is busy.
 */
function list({ search } = {}) {
  const rows = stmts.listAllUsers.all();
  const needle = String(search || '').trim().toLowerCase();
  const filtered = needle
    ? rows.filter(
        (r) =>
          String(r.email).toLowerCase().includes(needle) ||
          String(r.name).toLowerCase().includes(needle),
      )
    : rows;
  return filtered.map(publicUser);
}

function get(id) {
  const row = stmts.getUserById.get(Number(id));
  return row ? publicUser(row) : null;
}

/**
 * Create a client account with an administrator-chosen password.
 *
 * Ordering mirrors the sign-up flow: MeshCentral first, portal row second, so a
 * database failure never leaves a portal account whose console login is missing.
 * If the row cannot be written the fresh MeshCentral account is removed again.
 *
 * `groups` is how many device groups to create up front (0-10). The first one
 * carries a default name; extra ones are numbered so the account has somewhere
 * to install the agent the moment it signs in.
 */
async function create({ name, email, password, plan, groups, access, ip }) {
  const input = validateAccountInput({ name, email, password });
  if (input.error) throw httpError(400, input.error, 'invalid_input');
  // Validate the optional access window before any MeshCentral call so a typo
  // cannot leave a console account behind.
  const window = access === undefined ? null : normaliseAccess(access);
  if (window && window.error) throw httpError(400, window.error, 'invalid_input');

  if (stmts.getUserByEmail.get(input.email)) {
    throw httpError(409, 'An account already exists for that email address', 'account_exists');
  }

  const mcUserid = provision.useridFor(input.email);
  const existingMc = await provision.getAccount(mcUserid);
  let adopted = false;

  if (existingMc) {
    // A console login without a portal row: attach it instead of failing, and
    // set the operator-supplied password so the credentials handed over work.
    await provision.setPassword(mcUserid, input.password);
    await provision.setRealName(mcUserid, input.name);
    await provision.setAccountLocked(mcUserid, false);
    adopted = true;
  } else {
    await provision.createAccount({ email: input.email, name: input.name, password: input.password });
  }

  const now = nowIso();
  let row;
  try {
    const info = stmts.insertManagedUser.run({
      email: input.email,
      name: input.name,
      mc_userid: mcUserid,
      status: 'active',
      plan: typeof plan === 'string' && plan.trim() ? plan.trim().slice(0, 32) : DEFAULT_PLAN,
      created_at: now,
      updated_at: now,
    });
    row = stmts.getUserById.get(info.lastInsertRowid);
  } catch (err) {
    if (!adopted) {
      try {
        await provision.deleteAccount(mcUserid);
      } catch (cleanupErr) {
        console.error('[users] rollback of ' + mcUserid + ' failed: ' + cleanupErr.message);
      }
    }
    throw err;
  }

  // A window on creation starts counting now, so the operator and the client
  // agree on the exact moment access ends.
  if (window && !window.clear) {
    const startedAt = new Date();
    const endsAt = new Date(startedAt.getTime() + window.hours * HOUR_MS);
    stmts.setUserTrial.run(
      'trial',
      row.plan || DEFAULT_PLAN,
      startedAt.toISOString(),
      endsAt.toISOString(),
      null,
      nowIso(),
      row.id,
    );
    row = stmts.getUserById.get(row.id);
  }

  const wanted = Math.max(0, Math.min(10, Number.isFinite(Number(groups)) ? Number(groups) : 1));
  const warnings = [];
  let created = 0;
  for (let i = 0; i < wanted; i += 1) {
    const groupName = i === 0 ? defaultGroupName(input.name) : defaultGroupName(input.name) + ' ' + (i + 1);
    try {
      await trial.createGroupForUser(row, groupName);
      created += 1;
    } catch (err) {
      warnings.push('Device group "' + groupName + '" was not created: ' + err.message);
      console.error('[users] group for ' + input.email + ' failed: ' + err.message);
    }
  }

  trial.logEvent(
    row.id,
    'admin_user_create',
    'by=' + (ip || 'admin') + ' groups=' + created + (adopted ? ' adopted_mc=1' : '') +
      (window && !window.clear ? ' access=' + window.hours + 'h' : ''),
    ip,
  );
  return { user: publicUser(stmts.listAllUsers.all().find((r) => r.id === row.id) || row), groups_created: created, warnings };
}

/** Re-set the password for a managed account and prove the new one works. */
async function resetPassword(id, password, ip) {
  const row = stmts.getUserById.get(Number(id));
  if (!row) throw httpError(404, 'Unknown account', 'not_found');
  if (row.role === 'admin') throw httpError(400, 'Change the administrator password from the account panel', 'admin_account');
  if (!row.mc_userid) throw httpError(409, 'This account has no console login yet', 'no_mc_account');

  const pwError = auth.validatePassword(typeof password === 'string' ? password : '');
  if (pwError) throw httpError(400, pwError, 'invalid_input');

  await provision.setPassword(row.mc_userid, password);
  // Confirm the console accepts the new secret before telling the operator it
  // does, so a silent MeshCentral failure cannot be reported as success.
  const authed = await provision.verifyCredentials(row.email, password).catch(() => false);
  stmts.touchLogin.run(row.last_login_at || nowIso(), nowIso(), row.id);
  trial.logEvent(row.id, 'admin_password_reset', 'verified=' + !!authed, ip);
  if (!authed) {
    throw httpError(502, 'The console did not accept the new password. Try again.', 'verify_failed');
  }
  return { ok: true, user: publicUser(stmts.listAllUsers.all().find((r) => r.id === row.id) || row) };
}

/** Rename a managed account (portal display name and console real name). */
async function rename(id, name, ip) {
  const row = stmts.getUserById.get(Number(id));
  if (!row) throw httpError(404, 'Unknown account', 'not_found');
  const clean = typeof name === 'string' ? name.trim().replace(/\s+/g, ' ') : '';
  if (clean.length < 2 || clean.length > 80) throw httpError(400, 'Name must be 2-80 characters', 'invalid_input');
  if (row.mc_userid) {
    await provision.setRealName(row.mc_userid, clean).catch((err) => {
      console.error('[users] console rename failed for ' + row.mc_userid + ': ' + err.message);
    });
  }
  stmts.setUserName.run(clean, nowIso(), row.id);
  trial.logEvent(row.id, 'admin_user_rename', clean, ip);
  return { user: publicUser(stmts.listAllUsers.all().find((r) => r.id === row.id) || row) };
}

/**
 * Suspend or reinstate an account. Suspension blocks the portal session on the
 * next request and locks the console login (MeshCentral siteadmin bit 32), so
 * neither surface stays usable.
 */
async function setStatus(id, status, ip) {
  const row = stmts.getUserById.get(Number(id));
  if (!row) throw httpError(404, 'Unknown account', 'not_found');
  if (row.role === 'admin') throw httpError(400, 'The administrator account cannot be suspended', 'admin_account');
  if (status !== 'active' && status !== 'suspended') throw httpError(400, 'Status must be active or suspended', 'invalid_input');

  if (row.mc_userid) {
    try {
      await provision.setAccountLocked(row.mc_userid, status === 'suspended');
    } catch (err) {
      throw httpError(502, 'The console could not update this account: ' + err.message, 'console_error');
    }
  }
  // Reactivating an account that still has time on its window keeps the window
  // (status 'trial' is what the lifecycle treats as time-limited).
  const windowStillRunning = row.trial_ends_at && new Date(row.trial_ends_at).getTime() > Date.now();
  const nextStatus = status === 'active' && windowStillRunning ? 'trial' : status;
  stmts.setUserStatus.run(nextStatus, nowIso(), row.id);
  trial.logEvent(row.id, 'admin_user_' + nextStatus, 'by=admin', ip);
  return { user: publicUser(stmts.listAllUsers.all().find((r) => r.id === row.id) || row) };
}

/**
 * Set, replace or clear the access window of a managed account.
 *
 * The window is stored in trial_started_at / trial_ends_at and the account is
 * moved to status 'trial' so the existing sweep enforces it (portal block and
 * console lock at expiry). purge_after is deliberately left NULL: an expired
 * operator-managed client is locked, never auto-deleted, so the operator can
 * extend it again later. Passing `null` restores unlimited access.
 */
async function setAccess(id, access, ip) {
  const row = stmts.getUserById.get(Number(id));
  if (!row) throw httpError(404, 'Unknown account', 'not_found');
  if (row.role === 'admin') {
    throw httpError(400, 'The administrator account always has unlimited access', 'admin_account');
  }
  if (row.status === 'suspended') {
    throw httpError(409, 'Reinstate this account before setting an access window', 'suspended_account');
  }
  if (row.status === 'purged') {
    throw httpError(409, 'This account was removed by the trial sweep and cannot be reactivated', 'purged_account');
  }

  const window = normaliseAccess(access);
  if (window.error) throw httpError(400, window.error, 'invalid_input');

  const startedAt = new Date();
  const endsAt = window.clear ? null : new Date(startedAt.getTime() + window.hours * HOUR_MS);

  stmts.setUserTrial.run(
    window.clear ? 'active' : 'trial',
    row.plan || DEFAULT_PLAN,
    window.clear ? null : startedAt.toISOString(),
    endsAt ? endsAt.toISOString() : null,
    null,
    nowIso(),
    row.id,
  );

  // An account that already expired has a locked console login. Give the
  // console back as soon as the operator restores access.
  let consoleUnlocked = null;
  if (row.mc_userid && row.status === 'expired') {
    try {
      await provision.setAccountLocked(row.mc_userid, false);
      consoleUnlocked = true;
    } catch (err) {
      consoleUnlocked = false;
      console.error('[users] console unlock failed for ' + row.mc_userid + ': ' + err.message);
    }
  }

  trial.logEvent(
    row.id,
    window.clear ? 'admin_access_clear' : 'admin_access_window',
    window.clear
      ? 'unlimited by=' + (ip || 'admin')
      : window.hours + 'h ends=' + endsAt.toISOString() + ' mc_unlock=' + consoleUnlocked,
    ip,
  );

  const updated = stmts.listAllUsers.all().find((r) => r.id === row.id) || stmts.getUserById.get(row.id);
  return { user: publicUser(updated), console_unlocked: consoleUnlocked };
}

/**
 * Delete an account and everything it owns: device groups in MeshCentral, the
 * portal group rows, the console login and finally the portal row.
 *
 * A console-side failure is logged and the local rows are still removed, so an
 * operator is never left with a half-deleted account they cannot retry.
 */
async function remove(id, ip) {
  const row = stmts.getUserById.get(Number(id));
  if (!row) throw httpError(404, 'Unknown account', 'not_found');
  if (row.role === 'admin') throw httpError(400, 'The administrator account cannot be deleted', 'admin_account');

  const groups = stmts.listMeshesForUser.all(row.id);
  let groupsDeleted = 0;
  for (const g of groups) {
    try {
      await provision.deleteDeviceGroup(g.meshid);
      groupsDeleted += 1;
    } catch (err) {
      console.error('[users] group delete failed for ' + g.meshid + ': ' + err.message);
    }
  }
  stmts.deleteMeshesForUser.run(row.id);

  let accountDeleted = false;
  if (row.mc_userid) {
    try {
      await provision.deleteAccount(row.mc_userid);
      accountDeleted = true;
    } catch (err) {
      console.error('[users] console delete failed for ' + row.mc_userid + ': ' + err.message);
    }
  }

  stmts.purgeTokensForUser.run(row.id, 'confirm');
  stmts.purgeTokensForUser.run(row.id, 'reset');
  stmts.deleteUser.run(row.id);
  trial.logEvent(null, 'admin_user_delete', row.email + ' groups=' + groupsDeleted + ' console=' + accountDeleted, ip);

  return { deleted: row.email, groups_deleted: groupsDeleted, console_deleted: accountDeleted };
}

module.exports = {
  list,
  get,
  create,
  resetPassword,
  rename,
  setStatus,
  setAccess,
  remove,
  validateAccountInput,
};
