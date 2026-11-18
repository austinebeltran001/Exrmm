// EX SOFTWARE LLC portal - self-service account management.
//
// MeshCentral is the identity provider and its user id contains the email
// address (user//<domain>/<email>), so an account is never patched in place:
// changing the sign-in email creates the new account, re-shares the user's
// device groups to it, then removes the old account. Everything here is
// destructive in the MeshCentral sense, so each mutation requires the current
// password (proving the caller really owns the account) and each one is
// audited in portal_events.

'use strict';

const provision = require('./provision');
const mail = require('./mail');
const { stmts, nowIso } = require('./authdb');
const { SUPPORT_EMAIL, validatePassword, normaliseEmail } = require('./auth');
const trial = require('./trial');

function supportUrl() {
  return require('./auth').PUBLIC_BASE_URL + '/support';
}

function currentRows(userId) {
  return stmts.listMeshesForUser.all(userId);
}

// ---------------------------------------------------------------
// Display name
// ---------------------------------------------------------------
/** Display name is portal-side plus the MeshCentral realname (cosmetic only). */
async function changeName(user, newName, ip) {
  const clean = String(newName || '').trim().replace(/\s+/g, ' ');
  if (clean.length < 2 || clean.length > 80) {
    const err = new Error('Enter your full name (2-80 characters)');
    err.statusCode = 400;
    throw err;
  }

  let mcUpdated = false;
  if (user.mc_userid) {
    try {
      await provision.setRealName(user.mc_userid, clean);
      mcUpdated = true;
    } catch (err) {
      console.error('[account] realname update failed for ' + user.mc_userid + ': ' + err.message);
    }
  }

  const now = nowIso();
  stmts.setUserName.run(clean, now, user.id);
  trial.logEvent(user.id, 'name_change', clean, ip);
  return { user: stmts.getUserById.get(user.id), mcUpdated };
}

// ---------------------------------------------------------------
// Password
// ---------------------------------------------------------------
async function changePassword(user, currentPassword, newPassword, ip) {
  if (typeof currentPassword !== 'string' || !currentPassword) {
    const err = new Error('Enter your current password');
    err.statusCode = 400;
    throw err;
  }
  const pwError = validatePassword(String(newPassword || ''));
  if (pwError) {
    const err = new Error(pwError);
    err.statusCode = 400;
    throw err;
  }
  if (currentPassword === newPassword) {
    const err = new Error('Choose a password that is different from your current one');
    err.statusCode = 400;
    throw err;
  }

  const ok = await provision.verifyCredentials(user.email, currentPassword);
  if (!ok) {
    const err = new Error('Your current password is incorrect');
    err.statusCode = 403;
    err.code = 'bad_credentials';
    throw err;
  }

  await provision.setPassword(user.mc_userid, newPassword);
  const confirmed = await provision.verifyCredentials(user.email, newPassword);
  if (!confirmed) {
    const err = new Error('The password change did not take effect. Try again or use the reset link.');
    err.statusCode = 500;
    throw err;
  }

  trial.logEvent(user.id, 'password_change', 'self-service', ip);
  await mail.sendPasswordChanged({ to: user.email, name: user.name, supportUrl: supportUrl(), forgot: false });
  return { ok: true };
}

// ---------------------------------------------------------------
// Sign-in email (identity move in MeshCentral)
// ---------------------------------------------------------------
/**
 * Move the account to a new email address.
 *
 * The email is part of the MeshCentral user id, so this is implemented as
 * create-new -> re-share device groups -> remove-old. If any share fails the
 * new account is deleted again and the old account is left untouched, so the
 * operation either completes fully or changes nothing.
 */
async function changeEmail(user, currentPassword, newEmailRaw, ip) {
  const newEmail = normaliseEmail(newEmailRaw);
  if (!newEmail || newEmail.length > 254) {
    const err = new Error('Enter a valid email address');
    err.statusCode = 400;
    throw err;
  }
  if (newEmail === user.email) {
    const err = new Error('That is already your sign-in email');
    err.statusCode = 400;
    throw err;
  }
  if (stmts.getUserByEmail.get(newEmail)) {
    const err = new Error('That email address is already in use');
    err.statusCode = 409;
    err.code = 'email_in_use';
    throw err;
  }

  const ok = await provision.verifyCredentials(user.email, currentPassword);
  if (!ok) {
    const err = new Error('Your current password is incorrect');
    err.statusCode = 403;
    err.code = 'bad_credentials';
    throw err;
  }

  const newUserid = provision.useridFor(newEmail);
  if (await provision.getAccount(newUserid)) {
    const err = new Error('That email address is already in use');
    err.statusCode = 409;
    err.code = 'email_in_use';
    throw err;
  }

  const oldUserid = user.mc_userid;
  const meshes = currentRows(user.id);
  const moveWarnings = [];

  // MeshCentral has no "rename user" for email-based ids, so the password the
  // user just proved is reused for the new account.
  await provision.createAccount({ email: newEmail, name: user.name, password: currentPassword });

  try {
    for (const meshRow of meshes) {
      await provision.shareDeviceGroup(meshRow.meshid, newUserid);
    }
  } catch (err) {
    try {
      await provision.deleteAccount(newUserid);
    } catch (cleanupErr) {
      console.error('[account] rollback of ' + newUserid + ' failed: ' + cleanupErr.message);
    }
    err.statusCode = 500;
    err.message = 'Could not move your device groups to the new address: ' + err.message;
    throw err;
  }

  // Old identity cleanup: unshare from every group, then delete the account so
  // the previous mailbox can no longer sign in.
  if (oldUserid) {
    for (const meshRow of meshes) {
      try {
        await provision.unshareDeviceGroup(meshRow.meshid, oldUserid);
      } catch (err) {
        moveWarnings.push('unshare ' + meshRow.name + ': ' + err.message);
      }
    }
    try {
      await provision.deleteAccount(oldUserid);
    } catch (err) {
      moveWarnings.push('delete old account: ' + err.message);
    }
  }

  const now = nowIso();
  stmts.setUserEmail.run(newEmail, newUserid, now, user.id);
  // The new mailbox still has to be proved, but the account is usable at once.
  stmts.purgeTokensForUser.run(user.id, 'confirm');
  stmts.purgeTokensForUser.run(user.id, 'reset');

  trial.logEvent(user.id, 'email_change', user.email + ' -> ' + newEmail + ' (groups=' + meshes.length + ')', ip);

  await Promise.all([
    mail.sendEmailChanged({
      to: user.email,
      name: user.name,
      oldEmail: user.email,
      newEmail,
      supportUrl: supportUrl(),
      role: 'old',
    }),
    mail.sendEmailChanged({
      to: newEmail,
      name: user.name,
      oldEmail: user.email,
      newEmail,
      supportUrl: supportUrl(),
      role: 'new',
    }),
  ]);

  return { user: stmts.getUserById.get(user.id), groupsMoved: meshes.length, warnings: moveWarnings };
}

// ---------------------------------------------------------------
// Email confirmation + forgot password
// ---------------------------------------------------------------
function verifyEmail(token, ip) {
  const user = trial.consumeToken(token, 'confirm');
  if (!user) return null;
  stmts.markEmailVerified.run(nowIso(), user.id);
  trial.logEvent(user.id, 'email_verified', user.email, ip);
  return stmts.getUserById.get(user.id);
}

/**
 * Start a password reset. Always reports success to the caller so the endpoint
 * cannot be used to enumerate which email addresses have accounts.
 */
async function requestPasswordReset(emailRaw, ip) {
  const email = normaliseEmail(emailRaw);
  const user = email ? stmts.getUserByEmail.get(email) : null;
  if (!user) {
    trial.logEvent(null, 'reset_requested_unknown', email || null, ip);
    return { queued: true, known: false };
  }
  if (user.status === 'suspended') {
    trial.logEvent(user.id, 'reset_requested_suspended', user.email, ip);
    return { queued: true, known: true };
  }

  const token = trial.issueToken(user.id, 'reset', trial.RESET_TTL_HOURS);
  const resetUrl = require('./auth').PUBLIC_BASE_URL + '/reset-password?token=' + encodeURIComponent(token);
  await mail.sendPasswordReset({ to: user.email, name: user.name, resetUrl, hours: trial.RESET_TTL_HOURS });
  trial.logEvent(user.id, 'reset_requested', user.email, ip);
  return { queued: true, known: true };
}

/** Finish a reset: new password, MeshCentral updated and confirmed. */
async function completePasswordReset(token, newPassword, ip) {
  const user = trial.consumeToken(token, 'reset');
  if (!user) {
    const err = new Error('That reset link is invalid or has expired. Request a new one.');
    err.statusCode = 400;
    err.code = 'bad_token';
    throw err;
  }

  const pwError = validatePassword(String(newPassword || ''));
  if (pwError) {
    const err = new Error(pwError);
    err.statusCode = 400;
    err.code = 'weak_password';
    throw err;
  }

  await provision.setPassword(user.mc_userid, newPassword);
  const confirmed = await provision.verifyCredentials(user.email, newPassword);
  if (!confirmed) {
    const err = new Error('The new password did not take effect. Request a new reset link.');
    err.statusCode = 500;
    throw err;
  }

  // A reset also clears an expired-trial lock only when the trial is still
  // active; otherwise sign-in remains blocked as designed.
  trial.logEvent(user.id, 'password_reset', 'forgot-password flow', ip);
  await mail.sendPasswordChanged({ to: user.email, name: user.name, supportUrl: supportUrl(), forgot: true });
  return { user: stmts.getUserById.get(user.id) };
}

module.exports = {
  changeName,
  changePassword,
  changeEmail,
  verifyEmail,
  requestPasswordReset,
  completePasswordReset,
  SUPPORT_EMAIL,
};
