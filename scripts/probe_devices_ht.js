// Read-only probe: does the portal's device listing surface live MeshCentral
// nodes for a given device group? Mirrors what /api/portal/devices returns.
//
//   node scripts/probe_devices_ht.js [group name]
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

const { authdb } = require('../backend/src/authdb');
const provision = require('../backend/src/provision');

(async () => {
  const wanted = process.argv[2] || 'Kate';
  const meshes = authdb.prepare('SELECT * FROM portal_meshes ORDER BY id ASC').all();
  const mesh = meshes.find((m) => m.name === wanted) || meshes[meshes.length - 1];
  if (!mesh) {
    console.log('no mesh rows in portal_meshes');
    process.exit(1);
  }
  const user = authdb.prepare('SELECT * FROM portal_users WHERE id = ?').get(mesh.user_id);
  console.log('mesh   :', mesh.id, JSON.stringify(mesh.name), mesh.meshid);
  console.log('user   :', user.id, user.email, 'mc_userid=' + user.mc_userid, 'status=' + user.status);
  const devices = await provision.listDevicesForUser(user.mc_userid);
  console.log('devices:', devices.length);
  for (const d of devices) console.log('  -', JSON.stringify(d));
  process.exit(0);
})().catch((err) => {
  console.error('probe failed:', err.message);
  process.exit(1);
});
