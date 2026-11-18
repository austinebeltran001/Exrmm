// Probe the shape of the 'meshes' and 'nodes' responses (links, node fields)
// so the portal can map MeshCentral state to portal users. Read-only.
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
  const res = await mesh.controlCommand(BASE, cookie, { action: 'meshes' });
  const list = res.meshes || [];
  console.log('mesh count: ' + list.length);
  for (const m of list) {
    console.log('\ngroup: ' + JSON.stringify(m.name) + '  mtype=' + m.mtype);
    console.log('  entry fields: ' + Object.keys(m).join(', '));
    console.log('  links: ' + JSON.stringify(m.links || null));
  }

  if (list.length) {
    const nodes = await mesh.controlCommand(BASE, cookie, { action: 'nodes', meshid: list[0]._id }); console.log('RAW nodes: ' + JSON.stringify(nodes).slice(0, 600));
    const nl = nodes.nodes || [];
    console.log('\nnodes in first group: ' + nl.length);
    if (nl.length) {
      console.log('  node fields: ' + Object.keys(nl[0]).join(', '));
      const n = nl[0];
      console.log('  sample: ' + JSON.stringify({
        _id: n._id, name: n.name, rname: n.rname, meshid: n.meshid, osdesc: n.osdesc,
        host: n.host, ip: n.ip, conn: n.conn, lastconnecttime: n.lastconnecttime, pwr: n.pwr,
      }));
    }
  }
  process.exit(0);
})().catch((e) => { console.error('FAILED: ' + e.message); process.exit(1); });
