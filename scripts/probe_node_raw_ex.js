#!/usr/bin/env node
'use strict';
const path = require('path');
process.chdir(path.join(__dirname, '..', 'backend'));
require(path.join(__dirname, '..', 'backend', 'node_modules', 'dotenv')).config({ path: path.join(__dirname, '..', '.env') });
const provision = require(path.join(__dirname, '..', 'backend', 'src', 'provision.js'));

const MESHID = process.argv[2] || 'mesh//ANCfy@bJZMecZd51@jDNptp58W4I2EiWyOfe8lgI59dhER7$zje1GjudRjtl1C2w';

(async () => {
  // 1. nodes action
  const resp = await provision.run({ action: 'nodes', meshid: provision.meshidFor(MESHID) });
  console.log('=== nodes action response keys ===');
  console.log(Object.keys(resp || {}));
  const nodes = (resp && resp.nodes) || {};
  console.log('node map keys:', Object.keys(nodes));
  const firstKey = Object.keys(nodes)[0];
  if (firstKey) {
    const v = nodes[firstKey];
    const n = Array.isArray(v) ? v[0] : v;
    console.log('\n=== one node record ===');
    console.log(JSON.stringify(n, null, 2).slice(0, 4000));
  }

  // 2. node detail action (per-node)
  if (firstKey && firstKey.startsWith('node//')) {
    try {
      const det = await provision.run({ action: 'node', nodeid: firstKey });
      console.log('\n=== node detail: conn/power fields ===');
      const rec = (det && det.node) || det;
      if (rec && typeof rec === 'object') {
        for (const k of Object.keys(rec)) {
          if (/conn|power|state|lastconn|agentauth/i.test(k)) {
            console.log('  ' + k + ' = ' + JSON.stringify(rec[k]));
          }
        }
        console.log('  (all keys: ' + Object.keys(rec).join(',') + ')');
      } else {
        console.log(JSON.stringify(det).slice(0, 1000));
      }
    } catch (e) {
      console.log('node detail failed:', e.message);
    }
  }

  // 3. meshes action with details
  try {
    const meshes = await provision.run({ action: 'meshes', details: 1 });
    const m = (meshes && meshes.meshes) ? meshes.meshes[provision.meshidFor(MESHID)] : null;
    console.log('\n=== meshes(details) connectivity fields ===');
    if (m) {
      for (const k of Object.keys(m)) {
        if (/conn|power|state/i.test(k)) console.log('  mesh.' + k + ' = ' + JSON.stringify(m[k]).slice(0, 400));
      }
      const links = m.links || {};
      const lk = Object.keys(links)[0];
      if (lk) {
        console.log('  link keys: ' + Object.keys(links[lk]).join(','));
        console.log('  link sample: ' + JSON.stringify(links[lk]).slice(0, 600));
      }
    } else {
      console.log('  mesh not present in meshes response');
    }
  } catch (e) {
    console.log('meshes action failed:', e.message);
  }
})().catch((e) => { console.log('FATAL:', e.message); process.exit(1); });
