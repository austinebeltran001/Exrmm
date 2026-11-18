// Probe the live MeshCentral control channel to confirm the exact command
// contracts the Ex Softwares LLC portal will rely on. Creates one clearly-marked
// test account + device group, then removes both at the end.
//
// Usage: node scripts/probe_mc_contracts.js
'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const path = require('path');
// Load .env without adding a dependency
const fs = require('fs');
const envPath = path.join(__dirname, '..', '.env');
for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
  if (!m) continue;
  let v = m[2].trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
  if (process.env[m[1]] === undefined) process.env[m[1]] = v;
}

const mesh = require(path.join(__dirname, '..', 'backend', 'src', 'meshclient.js'));

const BASE = process.env.MESH_URL;
const DOMAIN = process.env.MESH_DOMAIN || '';
const TEST_EMAIL = 'ht-probe@hackertreats.com';
const TEST_USERID = 'user/' + DOMAIN + '/' + TEST_EMAIL;
const TEST_PASS = 'Probe-Password-2026!';
const TEST_GROUP = 'HT Probe Group';

function show(label, obj) {
  console.log('\n--- ' + label + ' ---');
  const text = JSON.stringify(obj);
  console.log(text.length > 900 ? text.slice(0, 900) + ' ...[truncated]' : text);
}

(async () => {
  console.log('MeshCentral: ' + BASE + ' user=' + process.env.MESH_USER);

  const { cookie } = await mesh.login(BASE, process.env.MESH_USER, process.env.MESH_PASS);
  console.log('login ok, cookie length=' + cookie.length);

  // 1. Who am I (siteadmin bits)
  const who = await mesh.controlCommand(BASE, cookie, { action: 'userinfo' });
  show('userinfo', who);

  // 2. Existing device group listing shape
  const meshes = await mesh.controlCommand(BASE, cookie, { action: 'meshes' });
  show('meshes keys', Object.keys(meshes));
  if (meshes.meshes) {
    show('meshes.meshes entries', (meshes.meshes || []).map((m) => ({ _id: m._id, name: m.name, mtype: m.mtype })));
  }

  // 3. Create the test account (email as username, pre-verified email)
  const add = await mesh.controlCommand(BASE, cookie, {
    action: 'adduser',
    username: TEST_EMAIL,
    pass: TEST_PASS,
    email: TEST_EMAIL,
    realname: 'Ex Softwares LLC Probe',
    emailVerified: true,
  });
  show('adduser', add);

  // 4. Create a device group as the admin account
  const cm = await mesh.controlCommand(BASE, cookie, {
    action: 'createmesh',
    meshname: TEST_GROUP,
    meshtype: 2,
    desc: 'probe',
  });
  show('createmesh', { result: cm.result, meshid: cm.meshid, links: cm.links, responseid: cm.responseid });
  const meshid = cm.meshid;

  // 5. Share the group with the test user (full rights on that group)
  if (meshid) {
    const amu = await mesh.controlCommand(BASE, cookie, {
      action: 'addmeshuser',
      meshid,
      meshadmin: 4294967295,
      userids: [TEST_USERID],
    });
    show('addmeshuser', amu);

    // 6. Can the test user see the group and create their own?
    const userLogin = await mesh.login(BASE, TEST_EMAIL, TEST_PASS);
    const userMeshes = await mesh.controlCommand(BASE, userLogin.cookie, { action: 'meshes' });
    show('test user meshes', (userMeshes.meshes || []).map((m) => ({ _id: m._id, name: m.name })));
    show('test user nodes keys', Object.keys(await mesh.controlCommand(BASE, userLogin.cookie, { action: 'nodes' })));

    const userCreate = await mesh.controlCommand(BASE, userLogin.cookie, {
      action: 'createmesh',
      meshname: 'HT Probe User Group',
      meshtype: 2,
    });
    show('test user createmesh', { result: userCreate.result, meshid: userCreate.meshid });

    const userDelete = await mesh.controlCommand(BASE, userLogin.cookie, {
      action: 'deletemesh',
      meshid: userCreate.meshid,
    });
    show('test user deletemesh', userDelete);

    // cleanup group
    show('deletemesh (admin)', await mesh.controlCommand(BASE, cookie, { action: 'deletemesh', meshid }));
  }

  // 7. Remove the test account
  show('deleteuser', await mesh.controlCommand(BASE, cookie, { action: 'deleteuser', userid: TEST_USERID }));

  console.log('\nprobe complete');
  process.exit(0);
})().catch((err) => {
  console.error('PROBE FAILED: ' + err.message);
  process.exit(1);
});
