// Read-only: enumerate nodes per device group and print the node record shape.
'use strict';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const path = require('path');
const fs = require('fs');
for (const line of fs.readFileSync(path.join(__dirname, '..', '.env'), 'utf8').split('\n')) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
  if (!m) continue;
  let v = m[2].trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
  if (process.env[m[1]] === undefined) process.env[m[1]] = v;
}

const mesh = require(path.join(__dirname, '..', 'backend', 'src', 'meshclient.js'));
const BASE = process.env.MESH_URL;

(async () => {
  const { cookie } = await mesh.login(BASE, process.env.MESH_USER, process.env.MESH_PASS);
  const meshes = (await mesh.controlCommand(BASE, cookie, { action: 'meshes' })).meshes || [];
  for (const m of meshes) {
    const res = await mesh.controlCommand(BASE, cookie, { action: 'nodes', meshid: m._id });
    const nodes = res.nodes || {};
    const ids = Object.keys(nodes);
    console.log('\n' + m.name + ' -> ' + ids.length + ' device(s)');
    if (ids.length) {
      const n = nodes[ids[0]];
      console.log('  node fields: ' + Object.keys(n).join(', '));
      console.log('  sample: ' + JSON.stringify({
        _id: n._id, name: n.name, rname: n.rname, meshid: n.meshid, osdesc: n.osdesc,
        host: n.host, ip: n.ip, conn: n.conn, lastconnecttime: n.lastconnecttime,
        pwr: n.pwr, agent: n.agent, rtype: n.rtype,
      }));
    }
  }
  process.exit(0);
})().catch((e) => { console.error('FAILED: ' + e.message); process.exit(1); });
