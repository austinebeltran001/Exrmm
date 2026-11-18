// Ex Softwares LLC portal - MeshCentral invalid-login throttling demo / regression check.
//
// MeshCentral keeps a "bad login" table keyed by client IP range by default
// (settings.maxinvalidlogin = { time: 10, count: 10, blocking: 'iprange' }).
// Every portal request reaches MeshCentral from the same backend address, so a
// handful of wrong passwords submitted through the portal trips the filter and
// blocks *all* logins from that range (admin integration included).
//
// This script:
//   1. ensures a probe user exists (with a known password),
//   2. fires `badCount` wrong-password logins,
//   3. tries the CORRECT password and an admin login,
//   4. reports whether MeshCentral served an authenticated session or a login
//      page (rate-limit markers included).
//
// Usage: node scripts/mc_lockout_demo_ht.js [badCount] [--keep]
//        --keep  leaves the probe account in place (default: deletes it)

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const WebSocket = require(path.join(__dirname, '..', 'backend', 'node_modules', 'ws'));

const ENV = {};
for (const line of fs.readFileSync(path.join(__dirname, '..', '.env'), 'utf8').split('\n')) {
  const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
  if (m) ENV[m[1]] = m[2].replace(/^"|"$/g, '');
}
const MESH_URL = ENV.MESH_URL;
const u = new URL(MESH_URL);
const base = u.pathname.replace(/\/+$/, '');

function login(username, password) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({ username, password }).toString();
    const req = https.request({
      hostname: u.hostname, port: u.port || 443, path: base + '/login', method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'ExSoftwaresPortal/1.0',
      },
      rejectUnauthorized: false,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        const cookies = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
        const xid = cookies.find((c) => c.startsWith('xid='));
        let payload = null;
        if (xid) { try { payload = JSON.parse(Buffer.from(xid.slice(4), 'base64').toString('utf8')); } catch (e) { payload = {}; } }
        resolve({
          ms: Date.now() - started,
          cookies: cookies.join('; '),
          payload: payload || {},
          authenticated: !!(payload && payload.userid),
          markers: {
            messageid114: /"messageid"\s*:\s*114/.test(text) || /messageid=114/.test(text),
            messageid110: /"messageid"\s*:\s*110/.test(text) || /messageid=110/.test(text),
            blockedText: /ip address blocked|account locked|too many/i.test(text),
          },
        });
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function control(cookie, command, timeoutMs) {
  return new Promise((resolve) => {
    const wsu = new URL(MESH_URL);
    wsu.protocol = wsu.protocol === 'http:' ? 'ws:' : 'wss:';
    wsu.pathname = base + '/control.ashx';
    const frames = [];
    const ws = new WebSocket(wsu.href, { rejectUnauthorized: false, headers: { Cookie: cookie } });
    const timer = setTimeout(() => { try { ws.close(); } catch (e) {} resolve({ ok: false, why: 'timeout', frames }); }, timeoutMs);
    const done = (r) => { clearTimeout(timer); try { ws.close(); } catch (e) {} resolve(r); };
    ws.on('open', () => ws.send(JSON.stringify(command)));
    ws.on('message', (d) => {
      const txt = d.toString('utf8');
      frames.push(txt.slice(0, 160));
      let m; try { m = JSON.parse(txt); } catch (e) { return; }
      if (m.action === 'close') return done({ ok: false, why: 'close cause=' + m.cause, frames });
      if (!command.responseid && m.action === command.action) return done({ ok: true, reply: m, frames });
    });
    ws.on('error', (e) => done({ ok: false, why: 'error ' + e.message, frames }));
    ws.on('close', (code) => done({ ok: false, why: 'close code=' + code, frames }));
  });
}

async function adminCmd(command) {
  const l = await login(ENV.MESH_USER, ENV.MESH_PASS);
  if (!l.authenticated) return { ok: false, why: 'admin login not authenticated (' + JSON.stringify(l.markers) + ')' };
  return control(l.cookies, Object.assign({ responseid: 'a_' + Math.random().toString(16).slice(2, 8) }, command), 15000);
}

(async () => {
  const args = process.argv.slice(2);
  const badCount = parseInt(args.find((a) => /^\d+$/.test(a)) || '11', 10);
  const keep = args.includes('--keep');
  const stamp = Date.now();
  const email = 'ht-lockout-' + stamp + '@example.com';
  const good = 'LockoutPass12345';

  console.log('=== MeshCentral invalid-login throttle demo (bad attempts: ' + badCount + ') ===');
  const add = await adminCmd({ action: 'adduser', username: email, pass: good, email, realname: 'Lockout Probe', emailVerified: true });
  console.log('probe account     -> ' + (add.ok ? 'created' : 'FAILED: ' + add.why));

  const before = await login(email, good);
  console.log('control login     -> authenticated=' + before.authenticated + ' (' + before.ms + 'ms)');

  for (let i = 1; i <= badCount; i++) {
    const bad = await login(email, 'WrongPassword' + i);
    process.stdout.write('bad login #' + i + ' -> authenticated=' + bad.authenticated + ' ms=' + bad.ms + '\n');
  }

  const after = await login(email, good);
  console.log('correct pw after  -> authenticated=' + after.authenticated + ' (' + after.ms + 'ms) markers=' + JSON.stringify(after.markers));
  const admin = await login(ENV.MESH_USER, ENV.MESH_PASS);
  console.log('admin after       -> authenticated=' + admin.authenticated + ' (' + admin.ms + 'ms) markers=' + JSON.stringify(admin.markers));
  console.log(admin.authenticated
    ? 'VERDICT: correct credentials still work (no platform-wide lockout)'
    : 'VERDICT: correct credentials are REFUSED -> IP-range lockout of the whole portal integration');

  if (!keep && admin.authenticated) {
    const del = await adminCmd({ action: 'deleteuser', userid: 'user//' + email });
    console.log('cleanup           -> ' + (del.ok ? 'probe account deleted' : del.why));
  } else if (!admin.authenticated) {
    console.log('cleanup           -> skipped, admin session blocked; probe account ' + email + ' left behind');
  }
})().catch((e) => { console.error('demo failed:', e.message); process.exit(1); });
