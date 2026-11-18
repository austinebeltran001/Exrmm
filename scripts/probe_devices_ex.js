#!/usr/bin/env node
'use strict';
// Probe: what MeshCentral returns for a portal account, and whether node.conn
// carries the "agent connected" bit that telegram.js relies on.
const path = require('path');
process.chdir(path.join(__dirname, '..', 'backend'));
require(path.join(__dirname, '..', 'backend', 'node_modules', 'dotenv')).config({ path: path.join(__dirname, '..', '.env') });

const provision = require(path.join(__dirname, '..', 'backend', 'src', 'provision.js'));
const MC_USERID = process.argv[2] || 'user//noreply@hackertreats.com';

(async () => {
  console.log('MESH_URL =', provision.MESH_URL);
  console.log('MESH_DOMAIN =', provision.MESH_DOMAIN);
  console.log('account =', MC_USERID, '\n');

  let groups = [];
  try {
    groups = await provision.listDeviceGroupsForUser(MC_USERID);
  } catch (err) {
    console.log('listDeviceGroupsForUser FAILED:', err.message, err.mcCode || '');
    process.exit(1);
  }

  console.log('device groups visible:', groups.length);
  for (const g of groups) console.log('  - ' + g.name + '  (' + g._id + ')');
  console.log('');

  const devices = await provision.listDevicesForUser(MC_USERID);
  console.log('devices:', devices.length);
  for (const d of devices) {
    console.log('  - ' + d.name + ' | group=' + d.group_name);
    console.log('      id=' + d.id);
    console.log('      online=' + d.online + '  os=' + d.os + '  ip=' + d.ip);
    console.log('      last_connect=' + d.last_connect);
  }

  console.log('\nraw conn bitmask per node:');
  for (const g of groups) {
    const resp = await provision.run({ action: 'nodes', meshid: provision.meshidFor(g._id) });
    const nodes = (resp && resp.nodes) || {};
    for (const key of Object.keys(nodes)) {
      const v = nodes[key];
      const arr = Array.isArray(v) ? v : [v];
      for (const n of arr) {
        if (!n) continue;
        console.log('  ' + (n.name || '(unnamed)') + ' -> conn=' + JSON.stringify(n.conn) + ' (typeof ' + typeof n.conn + ')');
      }
    }
  }
})().catch((err) => { console.log('FATAL:', err.message); process.exit(1); });
