#!/usr/bin/env node
'use strict';
const path = require('path');
process.chdir(path.join(__dirname, '..', 'backend'));
require(path.join(__dirname, '..', 'backend', 'node_modules', 'dotenv')).config({ path: path.join(__dirname, '..', '.env') });
const provision = require(path.join(__dirname, '..', 'backend', 'src', 'provision.js'));

const MESHID = process.argv[2] || 'mesh//ANCfy@bJZMecZd51@jDNptp58W4I2EiWyOfe8lgI59dhER7$zje1GjudRjtl1C2w';

(async () => {
  const resp = await provision.run({ action: 'nodes', meshid: provision.meshidFor(MESHID) });
  const nodesMap = (resp && resp.nodes) || {};
  const all = [];
  for (const k of Object.keys(nodesMap)) {
    const v = nodesMap[k];
    for (const n of (Array.isArray(v) ? v : [v])) if (n) all.push(n);
  }
  console.log('nodes found:', all.length);

  for (const n of all) {
    console.log('\n--- ' + n.name + '  ' + n._id);
    for (const action of ['node', 'nodes']) {
      try {
        const r = action === 'node'
          ? await provision.run({ action: 'node', nodeid: n._id })
          : null;
        if (!r) continue;
        const rec = r.node || r;
        const connKeys = Object.keys(rec).filter((k) => /conn|power|state|lastconn/i.test(k));
        console.log('  [node action] keys of interest: ' + connKeys.map((k) => k + '=' + JSON.stringify(rec[k])).join('  ') || '  (none)');
        if (!connKeys.length) console.log('  [node action] all keys: ' + Object.keys(rec).join(','));
      } catch (e) {
        console.log('  [node action] failed: ' + e.message);
      }
    }
  }

  // meshes action: look for the whole response shape
  const meshes = await provision.run({ action: 'meshes' });
  const m = (meshes && meshes.meshes) || {};
  const mk = Object.keys(m);
  console.log('\nmeshes response mesh keys:', mk.length);
  if (mk.length) {
    const first = m[mk[0]];
    console.log('mesh fields: ' + Object.keys(first).join(','));
    const links = first.links || {};
    const lk = Object.keys(links);
    console.log('link count: ' + lk.length);
    if (lk.length) console.log('link sample keys: ' + Object.keys(links[lk[0]]).join(',') + ' -> ' + JSON.stringify(links[lk[0]]).slice(0, 300));
  }
})().catch((e) => { console.log('FATAL:', e.message); process.exit(1); });
