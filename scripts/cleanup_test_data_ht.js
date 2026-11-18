// Ex Softwares LLC portal - remove test residue created by the verification scripts.
//
// Earlier end-to-end runs could not clean up after themselves (the MeshCentral
// login lockout broke the admin control channel mid-run), which left accounts,
// device groups and portal rows behind. This script removes only addresses that
// match the test pattern '^ht-...@example.com'; real users are never touched.
//
// Usage: node scripts/cleanup_test_data_ht.js [--dry-run]

'use strict';

const path = require('path');
require(path.join(__dirname, '..', 'backend', 'node_modules', 'dotenv')).config({
  path: path.join(__dirname, '..', '.env'),
});
const provision = require(path.join(__dirname, '..', 'backend', 'src', 'provision'));
const { db } = require(path.join(__dirname, '..', 'backend', 'src', 'db'));

const DRY_RUN = process.argv.includes('--dry-run');
const TEST_EMAIL = /^ht-[a-z0-9-]+@example\.com$/;

(async () => {
  console.log('=== cleanup of portal test data' + (DRY_RUN ? ' (dry run)' : '') + ' ===');

  const accounts = await provision.listAccounts();
  const groups = await provision.listDeviceGroups();
  const testAccounts = accounts.filter((u) => TEST_EMAIL.test(String(u._id).replace(/^user\/\//, '')));

  let removedGroups = 0;
  for (const acct of testAccounts) {
    const owned = groups.filter((m) => m.links && m.links[acct._id]);
    for (const m of owned) {
      console.log('  group ' + m._id + ' ("' + m.name + '") -> ' + (DRY_RUN ? 'would delete' : 'deleting'));
      if (!DRY_RUN) {
        try { await provision.deleteDeviceGroup(m._id); removedGroups += 1; }
        catch (err) { console.log('    failed: ' + err.message); }
      }
    }
    console.log('  account ' + acct._id + ' -> ' + (DRY_RUN ? 'would delete' : 'deleting'));
    if (!DRY_RUN) {
      try { await provision.deleteAccount(acct._id); }
      catch (err) { console.log('    failed: ' + err.message); }
    }
  }

  const portalUsers = db.prepare('SELECT id,email FROM portal_users').all().filter((u) => TEST_EMAIL.test(u.email));
  for (const u of portalUsers) {
    console.log('  portal user #' + u.id + ' ' + u.email + ' -> ' + (DRY_RUN ? 'would remove' : 'removing rows'));
    if (!DRY_RUN) {
      db.prepare('DELETE FROM portal_meshes WHERE user_id = ?').run(u.id);
      db.prepare('DELETE FROM portal_tokens WHERE user_id = ?').run(u.id);
      db.prepare('DELETE FROM portal_events WHERE user_id = ?').run(u.id);
      db.prepare('DELETE FROM portal_users WHERE id = ?').run(u.id);
    }
  }

  const remainingAccounts = (await provision.listAccounts()).filter((u) => TEST_EMAIL.test(String(u._id).replace(/^user\/\//, '')));
  const remainingGroups = (await provision.listDeviceGroups()).filter((m) => /Devices$|Renamed$/.test(String(m.name)) && Object.keys(m.links || {}).some((k) => TEST_EMAIL.test(String(k).replace(/^user\/\//, ''))));
  console.log('--- accounts removed=' + testAccounts.length + ' groups removed=' + removedGroups +
    ' portal rows removed=' + portalUsers.length +
    ' remaining test accounts=' + remainingAccounts.length + ' remaining linked groups=' + remainingGroups.length + ' ---');
})().catch((err) => { console.error('cleanup failed: ' + err.message); process.exit(1); });
