// Remove the Linux enrollment-test nodes created from this server itself.
// Only nodes whose display name matches the local hostname are deleted, so
// real customer devices are untouched.
//
//   node scripts/cleanup_probe_nodes_ht.js [hostname] [path-to-meshcentral.db-copy]
'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const path = require('path');
const fs = require('fs');
const os = require('os');
const root = path.join(__dirname, '..');
for (const line of fs.readFileSync(path.join(root, '.env'), 'utf8').split('\n')) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
  if (!m) continue;
  let v = m[2].trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
  if (process.env[m[1]] === undefined) process.env[m[1]] = v;
}

const meshclient = require('../backend/src/meshclient');

const TARGET = process.argv[2] || os.hostname();
const DBPATH = process.argv[3] || '/tmp/ht_mc.db';

function nodeIdsMatching(file, name) {
  const ids = [];
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let doc;
    try {
      doc = JSON.parse(trimmed);
    } catch (e) {
      continue;
    }
    if (!String(doc._id || '').startsWith('node//')) continue;
    if (doc.name === name) ids.push(doc._id);
  }
  return Array.from(new Set(ids));
}

(async () => {
  const ids = nodeIdsMatching(DBPATH, TARGET);
  if (!ids.length) {
    console.log('no test nodes named', TARGET, 'in', DBPATH);
    process.exit(0);
  }
  console.log('found', ids.length, 'node(s) named', TARGET);
  const session = await meshclient.login(process.env.MESH_URL, process.env.MESH_USER, process.env.MESH_PASS);
  await meshclient.controlCommandNoReply(process.env.MESH_URL, session.cookie, { action: 'removedevices', nodeids: ids }, 2500);
  console.log('sent removedevices for', ids.length, 'node(s)');
  process.exit(0);
})().catch((err) => {
  console.error('cleanup failed:', err.message);
  process.exit(1);
});
