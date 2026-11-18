// EX SOFTWARE LLC portal - trial provisioning and the 24-hour trial lifecycle.
//
// Sign-up provisions a normal (non-administrator) MeshCentral account, a
// self-owned device group, and a 24-hour trial window. A sweep runs every few
// minutes and moves accounts through three states:
//
//   trial  --(trial_ends_at)-->  expired  --(purge_after)-->  purged
//            sign-in blocked     account locked at MeshCentral level
//            "ending soon" mail  devices + account deleted, final mail sent
//
// Every MeshCentral call is idempotent-safe for repeated sweeps: locking an
// already-locked account and deleting an already-deleted account both succeed
// without side effects, and the portal row records what has been done so a
// retry after a crash does not repeat a destructive step blindly.

'use strict';

const crypto = require('crypto');

const provision = require('./provision');
const mail = require('./mail');
const { stmts, nowIso, isoPlusHours } = require('./authdb');
const { PUBLIC_BASE_URL, SUPPORT_EMAIL } = require('./auth');

const TRIAL_HOURS = parseInt(process.env.TRIAL_HOURS || '24', 10);
const WARN_HOURS = parseInt(process.env.WARN_HOURS || '4', 10);
// Workspace deletion happens this many hours after the trial started, i.e. 24
// hours after the 24-hour trial ends.
const PURGE_AFTER_START_HOURS = parseInt(process.env.PURGE_AFTER_START_HOURS || '48', 10);
const CONFIRM_TTL_HOURS = parseInt(process.env.CONFIRM_TTL_HOURS || '48', 10);
const RESET_TTL_HOURS = parseInt(process.env.RESET_TTL_HOURS || '2', 10);

const SWEEP_INTERVAL_MS = parseInt(process.env.SWEEP_INTERVAL_MS || String(5 * 60 * 1000), 10);

function portalUrl() {
  return PUBLIC_BASE_URL + '/';
}

function supportUrl() {
  return PUBLIC_BASE_URL + '/support';
}

function consoleUrl() {
  return require('./provision').MESH_URL + '/';
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * Issue a single-use token of the given kind, invalidating older tokens of the
 * same kind for that user. Only the SHA-256 hash is stored, so a database leak
 * does not hand out working reset links.
 */
function issueToken(userId, kind, ttlHours) {
  const raw = crypto.randomBytes(32).toString('base64url');
  stmts.purgeTokensForUser.run(userId, kind);
  stmts.insertToken.run(userId, kind, hashToken(raw), isoPlusHours(ttlHours), nowIso());
  return raw;
}

/** Consume a token (single use) and return the owning portal user row. */
function consumeToken(raw, kind) {
  if (typeof raw !== 'string' || raw.length < 16) return null;
  const row = stmts.getToken.get(hashToken(raw), kind);
  if (!row || row.used_at || row.expires_at <= nowIso()) return null;
  stmts.useToken.run(nowIso(), row.id);
  return stmts.getUserById.get(row.user_id) || null;
}

function logEvent(userId, kind, detail, ip) {
  try {
    stmts.logEvent.run(userId || null, kind, detail || null, ip || null, nowIso());
  } catch (err) {
    console.error('[trial] event log failed (' + kind + '): ' + err.message);
  }
}

function defaultGroupName(name) {
  const first = String(name || '').trim().split(/\s+/)[0];
  const base = first && first.length >= 2 ? first : 'My';
  return base + "'s Devices";
}

// ---------------------------------------------------------------
// Sign-up
// ---------------------------------------------------------------
/**
 * Create the portal record, the MeshCentral account (regular user rights only,
 * never siteadmin) and the user's first device group.
 *
 * Ordering is deliberate: the MeshCentral account is created first, then the
 * portal row. If the portal row cannot be written the MeshCentral account is
 * deleted again, so a failed sign-up does not leave an orphan login behind.
 */
async function startTrial({ name, email, password, ip, flow = 'direct' }) {
  const cleanEmail = String(email).trim().toLowerCase();
  const cleanName = String(name).trim();

  if (stmts.getUserByEmail.get(cleanEmail)) {
    const err = new Error('An account already exists for that email address. Sign in or reset your password.');
    err.code = 'account_exists';
    throw err;
  }

  // A MeshCentral account may exist without a portal row (e.g. created by an
  // administrator). Refuse to hijack it.
  const existingMc = await provision.getAccount(provision.useridFor(cleanEmail));
  if (existingMc) {
    const err = new Error('An account already exists for that email address. Sign in or reset your password.');
    err.code = 'account_exists';
    throw err;
  }

  const account = await provision.createAccount({ email: cleanEmail, name: cleanName, password });
  const mcUserid = account.mcUserid;

  let user;
  try {
    const now = nowIso();
    const info = stmts.insertUser.run({
      email: cleanEmail,
      name: cleanName,
      mc_userid: mcUserid,
      status: 'trial',
      plan: 'trial',
      trial_started_at: now,
      trial_ends_at: isoPlusHours(TRIAL_HOURS),
      purge_after: isoPlusHours(PURGE_AFTER_START_HOURS),
      created_at: now,
      updated_at: now,
    });
    user = stmts.getUserById.get(info.lastInsertRowid);
  } catch (err) {
    try {
      await provision.deleteAccount(mcUserid);
    } catch (cleanupErr) {
      console.error('[trial] rollback of ' + mcUserid + ' failed: ' + cleanupErr.message);
    }
    throw err;
  }

  // First device group. A failure here is not fatal: the user can create a
  // group from the dashboard once they sign in.
  let groupWarning = null;
  try {
    await createGroupForUser(user, defaultGroupName(cleanName));
  } catch (err) {
    groupWarning = err.message;
    console.error('[trial] default group for ' + cleanEmail + ' failed: ' + err.message);
  }

  logEvent(user.id, 'signup', 'trial started (' + TRIAL_HOURS + 'h)', ip);

  if (flow === 'credentials') {
    // Access-request flow: the credentials email itself goes to the address,
    // so receiving it proves ownership. No separate confirmation round-trip.
    stmts.markEmailVerified.run(nowIso(), user.id);
    user = stmts.getUserById.get(user.id);
    await mail.sendAccessGranted({
      to: cleanEmail,
      name: cleanName,
      email: cleanEmail,
      password,
      portalUrl: portalUrl(),
      consoleUrl: consoleUrl(),
      trialEndsAt: user.trial_ends_at,
    });
    return { user, groupWarning };
  }

  const confirmToken = issueToken(user.id, 'confirm', CONFIRM_TTL_HOURS);
  const confirmUrl = PUBLIC_BASE_URL + '/confirm-email?token=' + encodeURIComponent(confirmToken);

  await Promise.all([
    mail.sendEmailConfirmation({ to: cleanEmail, name: cleanName, confirmUrl }),
    mail.sendTrialStarted({
      to: cleanEmail,
      name: cleanName,
      consoleUrl: consoleUrl(),
      portalUrl: portalUrl(),
      trialEndsAt: user.trial_ends_at,
    }),
  ]);

  return { user, groupWarning };
}

// ---------------------------------------------------------------
// Device groups (portal-owned groups shared with the trial user)
// ---------------------------------------------------------------
async function createGroupForUser(user, name) {
  const group = await provision.createDeviceGroup({
    name,
    description: 'EX SOFTWARE LLC device group',
    ownerMcUserid: user.mc_userid,
  });
  stmts.insertMesh.run(user.id, group.meshid, name, nowIso());
  return stmts.getMeshByMeshid.get(group.meshid);
}

/** Delete one portal device group in MeshCentral, then remove the local row. */
async function deleteGroupForUser(user, meshRow) {
  try {
    await provision.deleteDeviceGroup(meshRow.meshid);
  } catch (err) {
    console.error('[trial] mesh delete failed for ' + meshRow.meshid + ': ' + err.message);
  }
  stmts.deleteMesh.run(meshRow.id);
  logEvent(user.id, 'group_delete', meshRow.name + ' (' + meshRow.meshid + ')');
}

// ---------------------------------------------------------------
// Trial sweep
// ---------------------------------------------------------------
function hoursLeftFor(row) {
  if (!row.trial_ends_at) return 0;
  const ms = new Date(row.trial_ends_at).getTime() - Date.now();
  return ms <= 0 ? 0 : Math.max(1, Math.round(ms / 3600000));
}

async function warnEndingSoon(row) {
  const hoursLeft = Math.min(WARN_HOURS, hoursLeftFor(row) || WARN_HOURS);
  const res = await mail.sendTrialEndingSoon({
    to: row.email,
    name: row.name,
    hoursLeft,
    supportUrl: supportUrl(),
  });
  const now = nowIso();
  stmts.setWarned.run(now, now, row.id);
  logEvent(row.id, 'trial_warning', 'hours_left=' + hoursLeft + ' sent=' + !!res.sent);
  return res;
}

/**
 * End the trial: block sign-in at the portal (status) and at MeshCentral
 * (siteadmin bit 32) so the console cannot be used either.
 */
async function expireTrial(row) {
  let locked = false;
  if (row.mc_userid) {
    try {
      const res = await provision.setAccountLocked(row.mc_userid, true);
      locked = true;
      console.log('[trial] locked ' + row.mc_userid + ' (siteadmin=' + res.siteadmin + ')');
    } catch (err) {
      console.error('[trial] lock failed for ' + row.mc_userid + ': ' + err.message);
    }
  }
  const now = nowIso();
  stmts.setExpired.run(now, now, row.id);
  logEvent(row.id, 'trial_expired', 'mc_locked=' + locked);
  await mail.sendTrialExpired({ to: row.email, name: row.name, supportUrl: supportUrl() });
}

/** Delete the trial workspace: all device groups, then the MeshCentral account. */
async function purgeUser(row) {
  const meshes = stmts.listMeshesForUser.all(row.id);
  for (const meshRow of meshes) {
    try {
      await provision.deleteDeviceGroup(meshRow.meshid);
    } catch (err) {
      console.error('[trial] purge: mesh delete failed for ' + meshRow.meshid + ': ' + err.message);
    }
  }
  stmts.deleteMeshesForUser.run(row.id);

  let accountDeleted = false;
  if (row.mc_userid) {
    try {
      await provision.deleteAccount(row.mc_userid);
      accountDeleted = true;
    } catch (err) {
      console.error('[trial] purge: account delete failed for ' + row.mc_userid + ': ' + err.message);
    }
  }
  stmts.purgeTokensForUser.run(row.id, 'confirm');
  stmts.purgeTokensForUser.run(row.id, 'reset');

  const now = nowIso();
  stmts.setPurged.run(now, now, row.id);
  logEvent(row.id, 'trial_purged', 'groups=' + meshes.length + ' account_deleted=' + accountDeleted);
  await mail.sendWorkspaceDeleted({ to: row.email, name: row.name, supportUrl: supportUrl() });
}

/** One lifecycle pass. Safe to call concurrently-ish; each step is idempotent. */
async function sweep() {
  const now = nowIso();
  const summary = { warned: 0, expired: 0, purged: 0, errors: [] };

  for (const row of stmts.listTrialsToWarn.all(now, isoPlusHours(WARN_HOURS))) {
    try {
      await warnEndingSoon(row);
      summary.warned += 1;
    } catch (err) {
      summary.errors.push('warn ' + row.email + ': ' + err.message);
    }
  }

  for (const row of stmts.listExpiredTrials.all(now)) {
    try {
      await expireTrial(row);
      summary.expired += 1;
    } catch (err) {
      summary.errors.push('expire ' + row.email + ': ' + err.message);
    }
  }

  for (const row of stmts.listUsersToPurge.all(now)) {
    try {
      await purgeUser(row);
      summary.purged += 1;
    } catch (err) {
      summary.errors.push('purge ' + row.email + ': ' + err.message);
    }
  }

  try {
    stmts.purgeStaleTokens.run(now);
  } catch (err) {
    summary.errors.push('token purge: ' + err.message);
  }

  return summary;
}

let sweepTimer = null;

function startSweeper() {
  if (sweepTimer) return sweepTimer;
  sweepTimer = setInterval(() => {
    sweep()
      .then((summary) => {
        if (summary.warned || summary.expired || summary.purged || summary.errors.length) {
          console.log(
            '[trial] sweep warned=' + summary.warned + ' expired=' + summary.expired + ' purged=' + summary.purged +
              (summary.errors.length ? ' errors=' + summary.errors.join(' | ') : '')
          );
        }
      })
      .catch((err) => console.error('[trial] sweep failed: ' + err.message));
  }, SWEEP_INTERVAL_MS);
  sweepTimer.unref();
  return sweepTimer;
}

/** Support-only: give a trial more time (clears the warning flag). */
function extendTrial(userId, extraHours) {
  const user = stmts.getUserById.get(userId);
  if (!user) throw new Error('Unknown portal user');
  const base = user.trial_ends_at && new Date(user.trial_ends_at) > new Date() ? new Date(user.trial_ends_at) : new Date();
  const ends = new Date(base.getTime() + extraHours * 3600 * 1000);
  const purge = new Date(ends.getTime() + (PURGE_AFTER_START_HOURS - TRIAL_HOURS) * 3600 * 1000);
  stmts.setUserTrial.run('trial', 'extended', user.trial_started_at || nowIso(), ends.toISOString(), purge.toISOString(), nowIso(), userId);
  logEvent(userId, 'trial_extended', '+' + extraHours + 'h -> ' + ends.toISOString());
  return stmts.getUserById.get(userId);
}

module.exports = {
  TRIAL_HOURS,
  WARN_HOURS,
  PURGE_AFTER_START_HOURS,
  RESET_TTL_HOURS,
  CONFIRM_TTL_HOURS,
  SUPPORT_EMAIL,
  startTrial,
  issueToken,
  consumeToken,
  createGroupForUser,
  deleteGroupForUser,
  jumpConsoleUrl: consoleUrl,
  sweep,
  startSweeper,
  extendTrial,
  logEvent,
};
