#!/usr/bin/env node
// Rebuild one device group's MSI through the portal's own builder module and
// print the embedded mesh policy so the binding can be verified.
'use strict';

const path = require('path');
const { buildMsi } = require(path.join(__dirname, '..', 'backend', 'src', 'msi'));
const { readMeshPolicy, meshIdFromPolicy } = require(path.join(__dirname, '..', 'backend', 'src', 'agentcache'));

const meshid = process.argv[2];
const name = process.argv[3];
if (!meshid || !name) {
  console.error('usage: rebuild_msi_ht.js <meshid> <group name>');
  process.exit(2);
}

(async () => {
  const built = await buildMsi({
    meshUrl: process.env.MESH_URL || 'https://remote.hackertreats.com',
    clientName: name,
    meshid,
    force: true,
  });
  console.log(JSON.stringify({ path: built.path, size: built.size, sha256: built.sha256, cached: built.cached }, null, 2));
  const agentExe = path.join(__dirname, '..', 'backend', 'agents', meshid.replace(/[^a-zA-Z0-9]/g, '_') + '.exe');
  const policy = readMeshPolicy(agentExe);
  console.log('agent policy MeshID :', policy ? meshIdFromPolicy(policy.msh) : 'NONE');
  console.log('agent ignoreProxyFile:', policy ? /^ignoreProxyFile=1$/m.test(policy.msh) : false);
  console.log('build log tail:', (built.buildLog || '').split('\n').slice(-5).join('\n'));
})().catch((err) => {
  console.error('BUILD FAILED: ' + err.message);
  process.exit(1);
});
