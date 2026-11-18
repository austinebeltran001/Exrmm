// Read-only probe: what device groups does the MeshCentral account the portal
// uses for administration actually see? Used to validate the "group still
// exists" guard before an MSI is built for it.
//
//   node scripts/probe_groups_ht.js
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

const meshclient = require('../backend/src/meshclient');

(async () => {
  const session = await meshclient.login(process.env.MESH_URL, process.env.MESH_USER, process.env.MESH_PASS);
  console.log('login ok, userid=', session.userid);
  const res = await meshclient.controlCommand(process.env.MESH_URL, session.cookie, { action: 'listdevicegroups' });
  const groups = Array.isArray(res) ? res : res.devicegroups || res.data || [];
  console.log('groups:', groups.length);
  for (const g of groups) {
    console.log('  -', g._id || g.meshid, '|', JSON.stringify(g.name), '| deleted=', g.deleted || null);
  }
  process.exit(0);
})().catch((e) => {
  console.error('probe failed:', e.message);
  process.exit(1);
});
