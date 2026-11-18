// Ex Softwares LLC portal - verify the per-account failed-verification cap.
//
// Regression test for the platform-wide login lockout: wrong passwords sent to
// /api/portal/login used to be forwarded to MeshCentral until MeshCentral's own
// invalid-login filter blocked the entire client address range (every portal
// user plus the admin integration). The portal now stops after 5 rejected
// verifications for the same account inside 15 minutes.
//
// Checks:
//   1. a fresh trial account signs up (portal + MeshCentral),
//   2. 7 wrong-password logins -> exactly the first VERIFY_FAIL_MAX are 401,
//      the rest are 429 account_throttled,
//   3. the admin/control channel is still healthy (no platform-wide lockout),
//   4. a DIFFERENT account can still sign in normally while account A is capped.
//
// Usage: node scripts/portal_login_throttle_ht.js

'use strict';

const path = require('path');
// The backend loads .env from server.js; this script drives the same modules
// directly, so it has to load the same configuration first.
require(path.join(__dirname, '..', 'backend', 'node_modules', 'dotenv')).config({
  path: path.join(__dirname, '..', '.env'),
});
const provision = require(path.join(__dirname, '..', 'backend', 'src', 'provision'));

// The portal backend is the only reachable path from this host (the public
// vhost is served through a separate ingress route), so test it directly.
const BASE = 'http://127.0.0.1:' + (process.env.PORT || '8090');
const STAMP = Date.now();
const ACCOUNT_A = { email: 'ht-throttle-a-' + STAMP + '@example.com', password: 'ThrottlePass12345' };
const ACCOUNT_B = { email: 'ht-throttle-b-' + STAMP + '@example.com', password: 'ThrottlePass12345' };

let failures = 0;
function check(label, ok, detail) {
  console.log((ok ? 'PASS  ' : 'FAIL  ') + label + (detail ? '  [' + detail + ']' : ''));
  if (!ok) failures++;
}

async function api(method, urlPath, body, cookie) {
  const headers = { 'Content-Type': 'application/json' };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(BASE + urlPath, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed = {};
  try { parsed = JSON.parse(text); } catch (e) { parsed = { raw: text.slice(0, 200) }; }
  const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  return { status: res.status, body: parsed, cookie: (setCookie[0] || '').split(';')[0] };
}

async function signup(account) {
  return api('POST', '/api/portal/signup', {
    name: 'Throttle Probe',
    email: account.email,
    password: account.password,
    password_confirm: account.password,
  });
}

(async () => {
  console.log('=== portal per-account verification cap (' + BASE + ') ===');
  const a = await signup(ACCOUNT_A);
  check('account A signs up', a.status === 201, 'status=' + a.status + ' ' + (a.body.error || ''));

  const statuses = [];
  for (let i = 1; i <= 7; i++) {
    const r = await api('POST', '/api/portal/login', { email: ACCOUNT_A.email, password: 'WrongPassword' + i });
    statuses.push(r.status + (r.body.code ? ':' + r.body.code : ''));
  }
  console.log('  wrong-password login statuses: ' + statuses.join(', '));
  const rejected = statuses.filter((s) => s.startsWith('401')).length;
  const throttled = statuses.filter((s) => s.startsWith('429')).length;
  check('first attempts rejected as bad credentials', rejected === 5, 'rejected=' + rejected);
  check('later attempts capped by the portal', throttled === 2, 'throttled=' + throttled);

  // The platform must still be usable: the admin control channel drives every
  // MeshCentral operation, so a broken channel means a broken platform.
  let adminOk = false;
  try {
    const users = await provision.listAccounts();
    adminOk = users.length > 0;
  } catch (err) {
    adminOk = false;
    console.log('  admin channel error: ' + err.message);
  }
  check('admin control channel still healthy', adminOk);

  // A different account is unaffected by account A being capped.
  const b = await signup(ACCOUNT_B);
  check('account B signs up', b.status === 201, 'status=' + b.status + ' ' + (b.body.error || ''));
  const bLogin = await api('POST', '/api/portal/login', { email: ACCOUNT_B.email, password: ACCOUNT_B.password });
  check('account B still signs in', bLogin.status === 200 && bLogin.body.user && bLogin.body.user.email === ACCOUNT_B.email, 'status=' + bLogin.status);

  const aLogin = await api('POST', '/api/portal/login', { email: ACCOUNT_A.email, password: ACCOUNT_A.password });
  check('capped account A is held off even with the right password', aLogin.status === 429, 'status=' + aLogin.status + ' code=' + aLogin.body.code);

  console.log('--- ' + (failures === 0 ? 'all checks passed' : failures + ' check(s) failed') + ' ---');
  console.log('cleanup: accounts ' + ACCOUNT_A.email + ', ' + ACCOUNT_B.email + ' are test data');
  process.exit(failures === 0 ? 0 : 1);
})().catch((err) => { console.error('probe failed: ' + err.message); process.exit(1); });
