// End-to-end self-test for backend/src/provision.js against the live
// MeshCentral server. Creates a throwaway account + device group, exercises
// every provisioning path, then removes everything it created.
//
// Usage: node scripts/provision_selftest.js
'use strict';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

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

const p = require(path.join(root, 'backend', 'src', 'provision.js'));

const EMAIL = 'ht-selftest-' + Date.now() + '@hackertreats.com';
const PASS = 'SelfTest-Pass-2026!';
const PASS2 = 'SelfTest-Pass-2026-New!';
const GROUP = 'HT SelfTest Group';

const results = [];
function check(name, cond, detail) {
  results.push({ name, ok: !!cond, detail });
  console.log((cond ? 'PASS  ' : 'FAIL  ') + name + (detail ? '  [' + detail + ']' : ''));
}

(async () => {
  let meshid = null;
  let mcUserid = null;
  try {
    // --- account creation + login ---
    const created = await p.createAccount({ email: EMAIL, name: 'Self Test', password: PASS });
    mcUserid = created.mcUserid;
    check('createAccount returns user//<email> id', mcUserid === 'user//' + EMAIL, mcUserid);
    check('new account authenticates with chosen password', await p.verifyCredentials(EMAIL, PASS));

    // --- duplicate signup is rejected ---
    let dup = null;
    try { await p.createAccount({ email: EMAIL, name: 'Dup', password: PASS }); } catch (e) { dup = e; }
    check('duplicate account is rejected', dup && dup.code === 'account_exists', dup && dup.mcResult);

    // --- account lookup ---
    const acct = await p.getAccount(mcUserid);
    check('getAccount finds the account', acct && acct._id === mcUserid, acct ? JSON.stringify({ siteadmin: acct.siteadmin, realname: acct.realname, email: acct.email, emailVerified: acct.emailVerified }) : 'null');

    // --- device group creation + sharing ---
    const group = await p.createDeviceGroup({ name: GROUP, ownerMcUserid: mcUserid });
    meshid = group.meshid;
    check('createDeviceGroup returns a mesh id', /^mesh\/\//.test(meshid || ''), meshid);

    const mine = await p.listDeviceGroupsForUser(mcUserid);
    check('group is shared with the portal user', mine.some((m) => m._id === meshid), 'groups=' + mine.length);
    check('shared group has full rights for the user', mine.some((m) => m._id === meshid && m.links && m.links[mcUserid] && m.links[mcUserid].rights === 4294967295));

    // --- device listing ---
    const nodes = await p.listNodes(meshid);
    check('listNodes returns an array', Array.isArray(nodes), 'count=' + nodes.length);
    const devices = await p.listDevicesForUser(mcUserid);
    check('listDevicesForUser returns an array', Array.isArray(devices), 'count=' + devices.length);

    // --- rename ---
    await p.renameDeviceGroup(meshid, 'HT SelfTest Renamed');
    const after = (await p.listDeviceGroups()).find((m) => m._id === meshid);
    check('renameDeviceGroup renames the group', after && after.name === 'HT SelfTest Renamed', after && after.name);

    // --- real name ---
    await p.setRealName(mcUserid, 'Self Test Renamed');
    const acct2 = await p.getAccount(mcUserid);
    check('setRealName updates the account name', acct2 && acct2.realname === 'Self Test Renamed', acct2 && acct2.realname);

    // --- account lock (trial expiry) ---
    await p.setAccountLocked(mcUserid, true);
    const locked = await p.getAccount(mcUserid);
    check('setAccountLocked sets siteadmin bit 32', locked && (locked.siteadmin & 32) === 32, 'siteadmin=' + (locked && locked.siteadmin));
    check('locked account cannot authenticate', (await p.verifyCredentials(EMAIL, PASS)) === false);

    await p.setAccountLocked(mcUserid, false);
    const unlocked = await p.getAccount(mcUserid);
    check('setAccountLocked clears bit 32', unlocked && (unlocked.siteadmin & 32) === 0, 'siteadmin=' + (unlocked && unlocked.siteadmin));
    check('unlocked account can authenticate again', await p.verifyCredentials(EMAIL, PASS));

    // --- admin password set ---
    await p.setPassword(mcUserid, PASS2);
    check('setPassword changes the stored password', await p.verifyCredentials(EMAIL, PASS2));
    check('old password no longer works', (await p.verifyCredentials(EMAIL, PASS)) === false);

    // --- unshare + delete group ---
    await p.unshareDeviceGroup(meshid, mcUserid);
    const notMine = await p.listDeviceGroupsForUser(mcUserid);
    check('unshareDeviceGroup removes user rights', !notMine.some((m) => m._id === meshid));
    await p.deleteDeviceGroup(meshid);
    const gone = (await p.listDeviceGroups()).find((m) => m._id === meshid);
    check('deleteDeviceGroup removes the group', !gone);
    meshid = null;

    // --- account deletion ---
    await p.deleteAccount(mcUserid);
    const deleted = await p.getAccount(mcUserid);
    check('deleteAccount removes the account', !deleted);
    mcUserid = null;
  } catch (err) {
    check('unexpected failure', false, err.message);
  } finally {
    // Safety net: never leave probe objects behind
    try { if (meshid) await p.deleteDeviceGroup(meshid); } catch (e) { console.log('cleanup group: ' + e.message); }
    try { if (mcUserid) await p.deleteAccount(mcUserid); } catch (e) { console.log('cleanup account: ' + e.message); }
  }

  const failed = results.filter((r) => !r.ok);
  console.log('\n' + (results.length - failed.length) + '/' + results.length + ' checks passed');
  process.exit(failed.length ? 1 : 0);
})();
