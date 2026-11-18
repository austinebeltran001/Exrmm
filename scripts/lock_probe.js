// DEBUG helper: create an account, lock it, and report login behaviour.
// Usage: node scripts/lock_probe.js create|check|delete
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
const EMAIL = 'ht-lockprobe@hackertreats.com';
const PASS = 'LockProbe-Pass-2026!';

(async () => {
  const mode = process.argv[2] || 'create';
  if (mode === 'create') {
    await p.createAccount({ email: EMAIL, name: 'Lock Probe', password: PASS });
    console.log('account created: ' + EMAIL + ' / ' + PASS);
    console.log('login before lock: ' + (await p.verifyCredentials(EMAIL, PASS)));
    await p.setAccountLocked(EMAIL ? p.useridFor(EMAIL) : null, true);
    const acct = await p.getAccount(p.useridFor(EMAIL));
    console.log('siteadmin now: ' + (acct && acct.siteadmin));
    console.log('portal verifyCredentials while locked: ' + (await p.verifyCredentials(EMAIL, PASS)));
  } else if (mode === 'check') {
    const acct = await p.getAccount(p.useridFor(EMAIL));
    console.log('account: ' + JSON.stringify(acct && { _id: acct._id, siteadmin: acct.siteadmin }));
    console.log('verifyCredentials: ' + (await p.verifyCredentials(EMAIL, PASS)));
  } else if (mode === 'delete') {
    console.log('delete: ' + JSON.stringify(await p.deleteAccount(p.useridFor(EMAIL))));
  }
  process.exit(0);
})().catch((e) => { console.error('FAILED: ' + e.message); process.exit(1); });
