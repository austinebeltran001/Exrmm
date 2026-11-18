// Ex Softwares LLC portal - end-to-end test of the self-service API.
//
// Drives the real HTTP API against the real MeshCentral instance (localhost,
// loopback only) and cleans up every account and device group it creates.
// Test addresses use example.com so no mail leaves the real mailbox, while the
// SMTP path itself is exercised (send results are logged, not asserted).
//
//   node scripts/portal_e2e.js
//
'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Same minimal .env loader the other scripts in this repository use (the
// scripts/ directory has no node_modules of its own).
const path = require('path');
const fs = require('fs');
const root = path.join(__dirname, '..');
for (const line of fs.readFileSync(path.join(root, '.env'), 'utf8').split('\n')) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
  if (!m) continue;
  let v = m[2].trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
  if (process.env[m[1]] === undefined) process.env[m[1]] = v;
}

const provision = require('../backend/src/provision');
const trial = require('../backend/src/trial');
const { stmts, nowIso, isoPlusHours } = require('../backend/src/authdb');

const BASE = 'http://127.0.0.1:' + (process.env.PORT || '8090');
const ADMIN_KEY = process.env.ADMIN_API_KEY;
const STAMP = Date.now().toString().slice(-8);
const EMAIL_1 = 'ht-e2e-' + STAMP + '@example.com';
const EMAIL_2 = 'ht-e2e-' + STAMP + '-moved@example.com';
const PASS_1 = 'TrialPass12345';
const PASS_2 = 'TrialPass67890';

let pass = 0;
let fail = 0;
let cookie = null;

function ok(name, detail) {
  pass += 1;
  console.log('PASS  ' + name + (detail ? '  [' + detail + ']' : ''));
}

function bad(name, detail) {
  fail += 1;
  console.log('FAIL  ' + name + (detail ? '  [' + detail + ']' : ''));
}

function check(name, condition, detail) {
  if (condition) ok(name, detail);
  else bad(name, detail);
  return !!condition;
}

async function api(method, path, body, useCookie = true, extraHeaders = {}) {
  const headers = Object.assign({}, extraHeaders);
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (useCookie && cookie) headers['Cookie'] = cookie;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of setCookie) {
    const pair = c.split(';')[0];
    if (pair.startsWith('ht_session=')) cookie = pair.endsWith('ht_session=') ? null : pair;
  }
  let json = null;
  const text = await res.text();
  try {
    json = text ? JSON.parse(text) : null;
  } catch (err) {
    json = { raw: text.slice(0, 200) };
  }
  return { status: res.status, body: json, headers: res.headers };
}

async function cleanup() {
  for (const email of [EMAIL_1, EMAIL_2]) {
    try {
      await provision.deleteAccount(provision.useridFor(email));
    } catch (err) {
      console.log('  cleanup: MC account ' + email + ' -> ' + err.message);
    }
    const row = stmts.getUserByEmail.get(email);
    if (row) {
      for (const m of stmts.listMeshesForUser.all(row.id)) {
        try {
          await provision.deleteDeviceGroup(m.meshid);
        } catch (err) {
          console.log('  cleanup: mesh ' + m.meshid + ' -> ' + err.message);
        }
      }
      stmts.deleteMeshesForUser.run(row.id);
      stmts.purgeTokensForUser.run(row.id, 'confirm');
      stmts.purgeTokensForUser.run(row.id, 'reset');
      require('../backend/src/db').db.prepare('DELETE FROM portal_users WHERE id = ?').run(row.id);
      require('../backend/src/db').db.prepare('DELETE FROM portal_events WHERE user_id = ?').run(row.id);
      console.log('  cleanup: portal row for ' + email + ' removed');
    }
  }
}

async function main() {
  console.log('--- portal e2e (test mailbox ' + EMAIL_1 + ') ---');

  // 0. config
  const cfg = await api('GET', '/api/portal/config', undefined, false);
  check('GET /api/portal/config returns trial length', cfg.status === 200 && cfg.body.trial_hours === 24, 'trial_hours=' + (cfg.body && cfg.body.trial_hours));

  // 1. signup
  const signup = await api('POST', '/api/portal/signup', {
    name: 'E2E Trial',
    email: EMAIL_1,
    password: PASS_1,
    password_confirm: PASS_1,
  }, false);
  check('POST /api/portal/signup creates a trial', signup.status === 201 && signup.body.user && signup.body.user.status === 'trial', 'status=' + signup.status + ' hours_left=' + (signup.body.user && signup.body.user.hours_left));
  check('signup issued a session cookie', !!cookie, cookie ? cookie.slice(0, 24) + '...' : 'none');
  check('trial window is 24 hours', signup.body.user && signup.body.user.hours_left > 23.5 && signup.body.user.hours_left <= 24, 'hours_left=' + (signup.body.user && signup.body.user.hours_left));
  check('purge is scheduled 48h after start', signup.body.user && signup.body.user.purge_after > signup.body.user.trial_ends_at, signup.body.user && signup.body.user.purge_after);

  // 2. weak password rejected
  const weak = await api('POST', '/api/portal/signup', {
    name: 'E2E Weak',
    email: 'ht-e2e-weak-' + STAMP + '@example.com',
    password: 'password',
    password_confirm: 'password',
  }, false);
  check('weak password rejected', weak.status === 400, weak.body && weak.body.error);

  // 3. duplicate signup
  const dup = await api('POST', '/api/portal/signup', {
    name: 'E2E Trial',
    email: EMAIL_1,
    password: PASS_1,
    password_confirm: PASS_1,
  }, false);
  check('duplicate signup rejected', dup.status === 409, dup.body && dup.body.error);

  // 4. the MeshCentral account is NOT an administrator
  const mcUserid = provision.useridFor(EMAIL_1);
  const mcAccount = await provision.getAccount(mcUserid);
  const siteadmin = mcAccount && typeof mcAccount.siteadmin === 'number' ? mcAccount.siteadmin : 0;
  check('MeshCentral account exists as a regular user', !!mcAccount && (siteadmin & 1) === 0, 'siteadmin=' + siteadmin);
  check('MeshCentral account is pre-verified', !!mcAccount && mcAccount.emailVerified === true, 'emailVerified=' + (mcAccount && mcAccount.emailVerified));

  // 5. session + groups
  cookie = cookie; // keep the signup cookie
  const me = await api('GET', '/api/portal/me');
  check('GET /api/portal/me returns the trial user', me.status === 200 && me.body.user.email === EMAIL_1);
  check('signup created one default device group', me.status === 200 && me.body.groups.length === 1, 'groups=' + (me.body.groups && me.body.groups.length));

  const groupRes = await api('POST', '/api/portal/groups', { name: 'Lab Rack' });
  check('POST /api/portal/groups creates a group', groupRes.status === 201 && groupRes.body.group.meshid, 'meshid=' + (groupRes.body.group && groupRes.body.group.meshid));
  const groupId = groupRes.body.group && groupRes.body.group.id;

  const agentRes = await api('GET', '/api/portal/groups/' + groupId + '/agent');
  const silentUrl = agentRes.body.agent && agentRes.body.agent.silent.x64;
  check('agent links point at the console host', agentRes.status === 200 && /^https:\/\/remote\.exsoftwares\.com\/api\/silent-agent\?id=4&installflags=2&meshid=/.test(String(silentUrl)), silentUrl);
  check('agent link carries the group mesh id', String(silentUrl).includes(encodeURIComponent(groupRes.body.group.meshid)));

  const rename = await api('PATCH', '/api/portal/groups/' + groupId, { name: 'Lab Rack Renamed' });
  check('PATCH renames a device group', rename.status === 200 && rename.body.group.name === 'Lab Rack Renamed', rename.body.group && rename.body.group.name);

  // ownership: a group id that does not belong to this user must 404
  const foreign = await api('GET', '/api/portal/groups/999999/agent');
  check('unknown group id is rejected', foreign.status === 404);

  // unauthenticated access
  const anon = await api('GET', '/api/portal/me', undefined, false);
  check('unauthenticated /me is rejected', anon.status === 401, 'status=' + anon.status);

  // 6. name change
  const nameRes = await api('POST', '/api/portal/account/name', { name: 'E2E Renamed' });
  const afterName = await provision.getAccount(mcUserid);
  check('POST /account/name updates the portal name', nameRes.status === 200 && nameRes.body.user.name === 'E2E Renamed', nameRes.body.user && nameRes.body.user.name);
  check('name change reaches the console account', !!afterName && afterName.realname === 'E2E Renamed', afterName && afterName.realname);

  // 7. password change
  const wrongPw = await api('POST', '/api/portal/account/password', { current_password: 'NotThePassword1', new_password: PASS_2 });
  check('password change requires the current password', wrongPw.status === 403, wrongPw.body && wrongPw.body.error);
  const pwChange = await api('POST', '/api/portal/account/password', { current_password: PASS_1, new_password: PASS_2 });
  check('POST /account/password succeeds', pwChange.status === 200, pwChange.body && pwChange.body.error);
  check('new password authenticates at MeshCentral', (await provision.verifyCredentials(EMAIL_1, PASS_2)) === true);
  check('old password no longer works', (await provision.verifyCredentials(EMAIL_1, PASS_1)) === false);

  // 8. email change (identity move)
  const emailChange = await api('POST', '/api/portal/account/email', { current_password: PASS_2, new_email: EMAIL_2 });
  check('POST /account/email moves the account', emailChange.status === 200 && emailChange.body.user.email === EMAIL_2, 'email=' + (emailChange.body.user && emailChange.body.user.email));
  check('email change moved every device group', emailChange.body.groups_moved === 2, 'groups_moved=' + emailChange.body.groups_moved);
  check('no warnings during the move', Array.isArray(emailChange.body.warnings) && emailChange.body.warnings.length === 0, JSON.stringify(emailChange.body.warnings));
  check('new MeshCentral identity exists and authenticates', (await provision.verifyCredentials(EMAIL_2, PASS_2)) === true);
  const oldAccount = await provision.getAccount(mcUserid);
  check('old MeshCentral identity is gone', !oldAccount, oldAccount ? 'still present' : 'deleted');
  const movedGroups = await api('GET', '/api/portal/groups');
  check('groups still visible after the move', movedGroups.status === 200 && movedGroups.body.groups.length === 2, 'groups=' + (movedGroups.body.groups && movedGroups.body.groups.length));

  // 9. login with the moved address
  cookie = null;
  const oldLogin = await api('POST', '/api/portal/login', { email: EMAIL_1, password: PASS_2 }, false);
  check('login with the old address fails', oldLogin.status === 401, 'status=' + oldLogin.status);
  const newLogin = await api('POST', '/api/portal/login', { email: EMAIL_2, password: PASS_2 }, false);
  check('login with the new address succeeds', newLogin.status === 200 && newLogin.body.user.email === EMAIL_2, 'status=' + newLogin.status);
  const badLogin = await api('POST', '/api/portal/login', { email: EMAIL_2, password: 'WrongPassword123' }, false);
  check('wrong password is rejected', badLogin.status === 401);

  // 10. forgot / reset password
  const forgot = await api('POST', '/api/portal/forgot', { email: EMAIL_2 }, false);
  check('POST /forgot always reports queued', forgot.status === 200 && forgot.body.ok === true);
  const forgotUnknown = await api('POST', '/api/portal/forgot', { email: 'nobody-' + STAMP + '@example.com' }, false);
  check('POST /forgot does not reveal unknown addresses', forgotUnknown.status === 200 && JSON.stringify(forgotUnknown.body) === JSON.stringify(forgot.body));

  const userRow = stmts.getUserByEmail.get(EMAIL_2);
  check('forgot created a reset token for the user', !!userRow);
  const tokenRow = require('../backend/src/db').db
    .prepare("SELECT COUNT(*) AS n FROM portal_tokens WHERE user_id = ? AND kind = 'reset' AND used_at IS NULL")
    .get(userRow.id);
  check('reset token stored (hashed) for the user', tokenRow.n === 1, 'tokens=' + tokenRow.n);
  const rawReset = trial.issueToken(userRow.id, 'reset', trial.RESET_TTL_HOURS); // raw value is never stored
  const reset = await api('POST', '/api/portal/reset', { token: rawReset, password: PASS_1, password_confirm: PASS_1 }, false);
  check('POST /reset sets a new password', reset.status === 200, reset.body && reset.body.error);
  check('reset password authenticates at MeshCentral', (await provision.verifyCredentials(EMAIL_2, PASS_1)) === true);
  const reuse = await api('POST', '/api/portal/reset', { token: rawReset, password: PASS_2, password_confirm: PASS_2 }, false);
  check('reset token cannot be reused', reuse.status === 400, reuse.body && reuse.body.error);
  const badToken = await api('POST', '/api/portal/reset', { token: 'x'.repeat(40), password: PASS_2, password_confirm: PASS_2 }, false);
  check('unknown reset token rejected', badToken.status === 400);

  // 11. audit trail
  const login2 = await api('POST', '/api/portal/login', { email: EMAIL_2, password: PASS_1 }, false);
  check('login works after reset', login2.status === 200, 'status=' + login2.status);
  const events = await api('GET', '/api/portal/events');
  const kinds = (events.body.events || []).map((e) => e.kind);
  check('audit trail records the account actions', ['signup', 'email_change', 'password_reset', 'login'].every((k) => kinds.includes(k)), kinds.join(','));

  // 12. expiry -> lock, then purge
  const db = require('../backend/src/db').db;
  db.prepare('UPDATE portal_users SET trial_ends_at = ? WHERE id = ?').run(isoPlusHours(-1), userRow.id);
  const expiredLogin = await api('POST', '/api/portal/login', { email: EMAIL_2, password: PASS_1 }, false);
  check('expired trial cannot sign in', expiredLogin.status === 403 && expiredLogin.body.code === 'trial_expired', 'status=' + expiredLogin.status);
  await new Promise((r) => setTimeout(r, 2500));
  const lockedAccount = await provision.getAccount(provision.useridFor(EMAIL_2));
  const expiredRow = stmts.getUserByEmail.get(EMAIL_2);
  check('sweep marked the trial expired', expiredRow.status === 'expired', 'status=' + expiredRow.status);
  check('expired account is locked at MeshCentral', !!lockedAccount && ((lockedAccount.siteadmin & 32) === 32), 'siteadmin=' + (lockedAccount && lockedAccount.siteadmin));

  const sweepNow = await api('POST', '/api/admin/trial-sweep', undefined, false, { 'X-Admin-Key': ADMIN_KEY });
  check('admin sweep endpoint runs', sweepNow.status === 200 && typeof sweepNow.body.purged === 'number', JSON.stringify(sweepNow.body));
  const noKey = await api('POST', '/api/admin/trial-sweep', undefined, false);
  check('sweep endpoint needs the admin key', noKey.status === 401);

  // Capture this run's own device groups: a global "no group is named ..."
  // assertion would also trip on residue from earlier test runs.
  const ownMeshIds = db.prepare('SELECT meshid FROM portal_meshes WHERE user_id = ?').all(userRow.id).map((r) => r.meshid);
  db.prepare('UPDATE portal_users SET purge_after = ? WHERE id = ?').run(isoPlusHours(-1), userRow.id);
  const purgeRun = await api('POST', '/api/admin/trial-sweep', undefined, false, { 'X-Admin-Key': ADMIN_KEY });
  const purgedRow = stmts.getUserByEmail.get(EMAIL_2);
  check('purge sweep ran', purgeRun.status === 200 && purgeRun.body.purged >= 1, 'purged=' + (purgeRun.body && purgeRun.body.purged));
  check('trial workspace marked purged', purgedRow.status === 'purged', 'status=' + purgedRow.status);
  const leftovers = (await provision.listDeviceGroups()).filter((m) => ownMeshIds.includes(m._id));
  check('device groups removed from MeshCentral', ownMeshIds.length > 0 && leftovers.length === 0, 'checked=' + ownMeshIds.length + ' leftover=' + leftovers.length);
  check('MeshCentral account deleted on purge', !(await provision.getAccount(provision.useridFor(EMAIL_2))));

  console.log('--- ' + pass + '/' + (pass + fail) + ' checks passed ---');
}

main()
  .catch((err) => {
    fail += 1;
    console.error('ERROR ' + err.stack);
  })
  .finally(async () => {
    await cleanup();
    console.log(fail === 0 ? 'ALL CHECKS PASSED' : fail + ' CHECK(S) FAILED');
    process.exit(fail === 0 ? 0 : 1);
  });
