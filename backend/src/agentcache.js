// EX SOFTWARE LLC portal - shared cache for MeshCentral Windows agent binaries.
//
// MeshCentral binds an agent to exactly one device group by appending a .msh
// "mesh policy" block to the executable:
//
//     <pe bytes> <msh text> <uint32 BE length> <16-byte policy GUID>
//
// Two failure modes have bitten this portal before, and both produce an
// installer that installs cleanly but never enrolls:
//
//   1. the mesh was deleted after the agent was cached, so the cached binary
//      points at a device group that no longer exists;
//   2. the server refuses the mesh and returns a short error body
//      ("Unauthorized"), which an earlier version cached as if it were an exe.
//
// So a cached binary is only reused when it still carries a valid policy
// trailer for the requested mesh id and is not older than MAX_AGE_MS. Anything
// else is re-downloaded, and a download that still lacks a matching policy is
// a hard error - never a silently broken installer.

'use strict';

const fs = require('fs');
const path = require('path');
const { downloadAgent } = require('./meshclient');

const AGENT_EXE_DIR = process.env.AGENT_EXE_DIR || path.join(__dirname, '..', 'agents');
const MAX_AGE_MS = Number(process.env.AGENT_CACHE_MAX_AGE_MS || 12 * 60 * 60 * 1000);

const MESH_POLICY_GUID = Buffer.from('B996015880544A19B7F7E9BE44914C19', 'hex');
const NULL_POLICY_GUID = Buffer.from('B996015880544A19B7F7E9BE44914C20', 'hex');

/**
 * Read the .msh block MeshCentral appended to an agent executable.
 * Returns { msh, guid, size } or null when the file has no policy trailer.
 */
function readMeshPolicy(file) {
  let fd;
  try {
    const { size } = fs.statSync(file);
    if (size < 1024) return null;
    fd = fs.openSync(file, 'r');
    const tail = Buffer.alloc(20);
    fs.readSync(fd, tail, 0, 20, size - 20);
    const guid = tail.subarray(4);
    if (!guid.equals(MESH_POLICY_GUID) && !guid.equals(NULL_POLICY_GUID)) return null;
    const mshLength = tail.readUInt32BE(0);
    if (mshLength <= 0 || mshLength > size - 20) return null;
    const mshBuf = Buffer.alloc(mshLength);
    fs.readSync(fd, mshBuf, 0, mshLength, size - 20 - mshLength);
    return { msh: mshBuf.toString('utf8'), guid: guid.toString('hex'), size: mshLength };
  } catch (err) {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Pull MeshID=0x... out of an .msh block, upper-cased without the 0x. */
function meshIdFromPolicy(msh) {
  const m = /^MeshID=0x([0-9A-Fa-f]+)\s*$/m.exec(msh || '');
  return m ? m[1].toUpperCase() : null;
}

/** MeshCentral's URL-safe mesh id: '@' stands in for '+' and '$' for '/'. */
function expectedHex(meshid) {
  const tail = String(meshid).split('//')[1] || String(meshid);
  const b64 = tail.replace(/@/g, '+').replace(/\$/g, '/');
  const raw = Buffer.from(b64, 'base64');
  return raw.length ? raw.toString('hex').toUpperCase() : null;
}

function cachePathFor(meshid) {
  return path.join(AGENT_EXE_DIR, String(meshid).replace(/[^a-zA-Z0-9]/g, '_') + '.exe');
}

function validateAgent(file, meshid) {
  const want = expectedHex(meshid);
  const policy = readMeshPolicy(file);
  if (!policy) {
    return { ok: false, reason: 'no mesh policy trailer (file is not a MeshCentral agent)' };
  }
  const got = meshIdFromPolicy(policy.msh);
  if (!got) {
    return { ok: false, reason: 'agent policy carries no MeshID' };
  }
  if (want && got !== want) {
    return { ok: false, reason: `agent policy is for mesh ${got.slice(0, 16)}..., expected ${want.slice(0, 16)}...` };
  }
  return { ok: true, msh: policy.msh };
}

/**
 * Return a path to a Windows agent whose embedded policy matches `meshid`,
 * downloading it when the cache is missing, stale or bound to another mesh.
 * Throws when the server will not hand out a valid agent for this mesh.
 */
async function resolveAgent(meshUrl, meshid) {
  fs.mkdirSync(AGENT_EXE_DIR, { recursive: true });
  const cached = cachePathFor(meshid);

  let staleReason = 'missing';
  if (fs.existsSync(cached)) {
    const check = validateAgent(cached, meshid);
    if (check.ok) {
      const age = Date.now() - fs.statSync(cached).mtimeMs;
      if (age <= MAX_AGE_MS) return { path: cached, cached: true, msh: check.msh };
      staleReason = `cached agent is ${Math.round(age / 3600000)}h old`;
    } else {
      staleReason = check.reason;
    }
  }

  const tmp = cached + '.download';
  try {
    await downloadAgent(meshUrl, meshid, tmp);
  } catch (err) {
    if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    throw new Error(`agent download failed for mesh ${String(meshid).slice(0, 16)}...: ${err.message}`);
  }

  const check = validateAgent(tmp, meshid);
  if (!check.ok) {
    const head = fs.readFileSync(tmp).subarray(0, 120).toString('utf8').replace(/[^\x20-\x7e]/g, '.');
    fs.unlinkSync(tmp);
    throw new Error(
      `MeshCentral did not return a usable agent for mesh ${String(meshid).slice(0, 16)}... ` +
        `(${check.reason}; ${staleReason}). Server body starts with: "${head}"`
    );
  }

  fs.renameSync(tmp, cached);
  return { path: cached, cached: false, msh: check.msh };
}

module.exports = { resolveAgent, validateAgent, readMeshPolicy, meshIdFromPolicy, expectedHex, cachePathFor };
