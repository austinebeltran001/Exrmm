// EX SOFTWARE LLC portal - single-click silent agent wrapper builder.
//
// MeshCentral's Windows agent always opens its install dialog when it is
// double-clicked, even with InstallFlags=2 ("Background only") baked in -
// InstallFlags only hides the Connect button inside that dialog. This module
// turns such a download into a small NSIS wrapper that elevates once (UAC) and
// then runs the real agent with `-fullinstall`, which installs completely
// silently.
//
// Flow per request:
//   1. fetch the agent from MeshCentral, WITH installflags=2 embedded, so the
//      payload is byte-identical to what the user selected;
//   2. render scripts/silent-wrapper-template.nsi around it;
//   3. compile with makensis;
//   4. cache by (agent id, mesh id, installflags) and serve the cached file.
//
// The agent is fetched from MeshCentral's internal listener (127.0.0.1:8443)
// on purpose:
//   * it bypasses the public edge, so this cannot recurse back into the
//     nginx interception rule for /meshagents;
//   * getWebServerName() derives the name baked into the agent from the
//     certificate CommonName (remote.exrmm.com), not from the request
//     Host header, so the internal fetch still produces
//     MeshServer=wss://remote.exrmm.com:443/agent.ashx. This was
//     verified by extracting the embedded settings from a live download.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const { nsiEscape, safeDirName } = require('./builder');
const { resolveMakensis } = require('./toolchain');

const TEMPLATE_PATH =
  process.env.SILENT_WRAPPER_TEMPLATE || path.join(__dirname, '..', '..', 'scripts', 'silent-wrapper-template.nsi');
const WRAPPER_DIR = process.env.SILENT_WRAPPERS_DIR || path.join(__dirname, '..', '..', 'installers', 'silent');
const AGENT_CACHE_DIR = process.env.SILENT_AGENTS_DIR || path.join(__dirname, '..', '..', 'agents', 'silent');

// Fingerprint of the NSIS wrapper template. Included in the wrapper cache key
// so that any change to the template (e.g. the ExecWait -> nsExec switch that
// removed the visible console window) automatically invalidates previously
// built wrappers instead of serving a stale binary from disk/cache.
const TEMPLATE_HASH = (() => {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(TEMPLATE_PATH)).digest('hex').slice(0, 12);
  } catch (err) {
    return 'template-unreadable';
  }
})();

// MeshCentral's internal HTTPS listener. Deliberately NOT the public URL: the
// public edge rewrites /meshagents?installflags=2 to this very service.
const MESH_INTERNAL_URL = (process.env.MESH_INTERNAL_URL || 'https://127.0.0.1:8443').replace(/\/+$/, '');

// MeshCentral agent type ids that are Windows executables.
const WINDOWS_AGENT_IDS = new Set(['3', '4', '43']);
// The only installflags value this service is willing to serve.
const BACKGROUND_ONLY_FLAGS = '2';

// Keep the on-disk cache bounded.
const MAX_CACHED_WRAPPERS = parseInt(process.env.SILENT_WRAPPER_CACHE_MAX || '20', 10);

// De-duplicates concurrent builds of the same wrapper.
const inFlight = new Map();

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function cacheKey(agentId, meshid, installFlags, key) {
  return sha256([agentId, meshid, installFlags, key || '', TEMPLATE_HASH].join('|')).slice(0, 32);
}

/**
 * MeshCentral stores device groups as "mesh/<domainid>/<shortid>" and expects
 * only the bare <shortid> in the ?meshid= query parameter of /meshagents.
 * Passing the full "mesh//<shortid>" makes the server look up
 * "mesh//mesh//<shortid>", find nothing and answer HTTP 401.
 */
function normalizeMeshId(meshid) {
  const s = String(meshid || '').trim();
  if (s.startsWith('mesh/')) {
    const parts = s.split('/');
    if (parts.length >= 3 && parts[2]) return parts[2];
  }
  return s;
}

/**
 * Pull the result file name out of an upstream Content-Disposition header.
 * MeshCentral sends e.g.  attachment; filename="meshagent64-AcmeCorp.exe"
 */
function filenameFromContentDisposition(header, fallback) {
  if (typeof header !== 'string') return fallback;
  let m = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (m) {
    try {
      return decodeURIComponent(m[1].trim());
    } catch (e) {
      /* fall through */
    }
  }
  m = /filename="?([^";]+)"?/i.exec(header);
  if (m) return m[1].trim();
  return fallback;
}

/** Strip anything that could escape the intended download name. */
function sanitizeFilename(name, fallback) {
  const base = path.basename(String(name || '')).replace(/[\x00-\x1f"\\/:*?<>|]+/g, '').trim();
  return base && base.toLowerCase().endsWith('.exe') ? base : fallback;
}

/**
 * GET an agent binary from MeshCentral's internal listener.
 * Returns { buffer, filename }.
 */
function fetchAgent({ agentId, meshid, installFlags, key, timeoutMs = 120000 }) {
  const u = new URL(MESH_INTERNAL_URL);
  const params = new URLSearchParams({ id: agentId, meshid: normalizeMeshId(meshid) });
  if (installFlags != null) params.set('installflags', installFlags);
  if (key) params.set('key', key);
  const reqPath = u.pathname.replace(/\/+$/, '') + '/meshagents?' + params.toString();

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: reqPath,
        method: 'GET',
        headers: { 'User-Agent': 'EXagentPortal/1.0' },
        rejectUnauthorized: false, // MeshCentral serves its own certificate internally
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          if (res.statusCode !== 200) {
            return reject(
              new Error('MeshCentral agent fetch failed: HTTP ' + res.statusCode + ' (' + body.length + ' bytes)')
            );
          }
          const fallback = 'meshagent64-' + agentId + '.exe';
          const filename = sanitizeFilename(
            filenameFromContentDisposition(res.headers['content-disposition'], fallback),
            fallback
          );
          resolve({ buffer: body, filename });
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error('MeshCentral agent fetch timed out')));
    req.end();
  });
}

/** Drop the oldest wrappers once the cache directory grows past the limit. */
function pruneCache() {
  try {
    const entries = fs
      .readdirSync(WRAPPER_DIR)
      .filter((f) => f.endsWith('.exe'))
      .map((f) => {
        const p = path.join(WRAPPER_DIR, f);
        return { p, mtime: fs.statSync(p).mtimeMs };
      })
      .sort((a, b) => b.mtime - a.mtime);
    for (const e of entries.slice(MAX_CACHED_WRAPPERS)) {
      fs.rmSync(e.p, { force: true });
      fs.rmSync(e.p.replace(/\.exe$/, '.json'), { force: true });
      fs.rmSync(e.p.replace(/\.exe$/, '.agent.exe'), { force: true });
    }
  } catch (e) {
    /* cache pruning is best effort */
  }
}

async function buildWrapper({ agentId, meshid, installFlags, key }) {
  const ck = cacheKey(agentId, meshid, installFlags, key);
  const outPath = path.join(WRAPPER_DIR, 'silent-' + ck + '.exe');
  const metaPath = path.join(WRAPPER_DIR, 'silent-' + ck + '.json');

  if (fs.existsSync(outPath) && fs.existsSync(metaPath)) {
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    if (fs.statSync(outPath).size === meta.size) {
      meta.path = outPath;
      meta.cached = true;
      return meta;
    }
  }

  const agentExe = path.join(WRAPPER_DIR, 'silent-' + ck + '.agent.exe');
  const buildDir = path.join(WRAPPER_DIR, 'build-' + ck);
  fs.mkdirSync(WRAPPER_DIR, { recursive: true });
  fs.mkdirSync(buildDir, { recursive: true });

  // 1. The real agent, with the flags the user actually selected baked in.
  const { buffer, filename } = await fetchAgent({ agentId, meshid, installFlags, key });
  if (buffer.length < 1024 || buffer.slice(0, 2).toString('latin1') !== 'MZ') {
    throw new Error('MeshCentral returned something that is not a Windows executable (' + buffer.length + ' bytes)');
  }
  fs.writeFileSync(agentExe, buffer);

  // 2. Render the wrapper template.
  const agentName = 'exagent-agent.exe';
  const nsi = fs
    .readFileSync(TEMPLATE_PATH, 'utf8')
    .split('{{OUTFILE}}').join(nsiEscape(outPath))
    .split('{{AGENT_EXE}}').join(nsiEscape(agentExe))
    .split('{{AGENT_NAME}}').join(nsiEscape(agentName))
    .split('{{PRODUCT_NAME}}').join(nsiEscape('EXagent'));
  const nsiPath = path.join(buildDir, 'wrapper.nsi');
  fs.writeFileSync(nsiPath, nsi);

  // 3. Compile.
  let buildLog;
  try {
    const r = await execFileAsync(resolveMakensis(), ['-V2', nsiPath], { maxBuffer: 10 * 1024 * 1024, timeout: 180000 });
    buildLog = (r.stdout || '') + (r.stderr || '');
  } catch (err) {
    const output = [err.stdout, err.stderr, err.message].filter(Boolean).join('\n');
    const e = new Error('makensis failed for silent wrapper:\n' + output);
    e.buildOutput = output;
    throw e;
  }

  if (!fs.existsSync(outPath) || fs.statSync(outPath).size < 1024) {
    throw new Error('makensis did not produce ' + outPath + '\n' + buildLog);
  }

  const meta = {
    path: outPath,
    filename: filename,
    size: fs.statSync(outPath).size,
    sha256: sha256(fs.readFileSync(outPath)),
    agent_size: buffer.length,
    agent_sha256: sha256(buffer),
    agent_id: agentId,
    installflags: installFlags,
    meshid: meshid,
    built_at: new Date().toISOString(),
    cached: false,
  };
  fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));
  fs.rmSync(buildDir, { recursive: true, force: true });
  pruneCache();
  return meta;
}

/**
 * Public entry point used by the API route.
 * Returns { path, filename, size, sha256, cached }.
 */
async function getSilentWrapper({ agentId, meshid, installFlags = BACKGROUND_ONLY_FLAGS, key }) {
  const id = String(agentId);
  if (!WINDOWS_AGENT_IDS.has(id)) {
    throw Object.assign(new Error('Unsupported agent id: ' + id), { statusCode: 400 });
  }
  if (!meshid || typeof meshid !== 'string') {
    throw Object.assign(new Error('meshid is required'), { statusCode: 400 });
  }
  if (String(installFlags) !== BACKGROUND_ONLY_FLAGS) {
    throw Object.assign(new Error('Only installflags=2 (Background only) is handled here'), { statusCode: 400 });
  }

  meshid = normalizeMeshId(meshid);

  const k = cacheKey(id, meshid, String(installFlags), key);
  if (inFlight.has(k)) return inFlight.get(k);

  const p = buildWrapper({ agentId: id, meshid, installFlags: String(installFlags), key })
    .finally(() => inFlight.delete(k));
  inFlight.set(k, p);
  return p;
}

module.exports = {
  getSilentWrapper,
  fetchAgent,
  normalizeMeshId,
  WINDOWS_AGENT_IDS,
  BACKGROUND_ONLY_FLAGS,
  WRAPPER_DIR,
  safeDirName,
};
