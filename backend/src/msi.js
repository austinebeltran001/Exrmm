// EX SOFTWARE LLC portal - Windows MSI installer builder (WiX source, wixl/msitools).
//
// Sibling of builder.js (the NSIS .exe installer). Same input - one device
// group - but the output is a per-machine .msi so the same agent can be pushed
// centrally with `msiexec /i exagent-setup.msi /qn` from Group Policy,
// Intune or SCCM instead of being run by hand on every machine.
//
//   1. reuse the cached MeshCentral Windows x64 agent (meshid baked in),
//      exactly the binary the NSIS installer wraps
//   2. render scripts/msi-template.wxs with the client parameters
//   3. run wixl -a x64 to produce installers/<client>/exagent-setup.msi
//
// The result is cached on disk: an existing MSI is reused while it is newer
// than both the template and the agent binary it embeds, so repeated downloads
// from the portal do not re-run wixl.
//
// On any wixl failure the FULL compiler output is attached to the thrown error
// so the caller can report it verbatim.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
// Windows has python.exe, Linux ships python3. Resolve the interpreter per
// platform (PYTHON overrides it, e.g. for a portable/virtualenv install).
const PYTHON = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const { resolveAgent } = require('./agentcache');
const { safeDirName, sha256File } = require('./builder');

const TEMPLATE_PATH = process.env.MSI_TEMPLATE || path.join(__dirname, '..', '..', 'scripts', 'msi-template.wxs');
// NSIS source of the console-less service runner embedded in every MSI. It is
// compiled by build_msi.py, and it is a build dependency of the MSI, so an
// edit to it must invalidate the cached MSI too.
const RUNNER_TEMPLATE_PATH = process.env.MSI_RUNNER_TEMPLATE || path.join(__dirname, '..', '..', 'scripts', 'msi-runner.nsi');
// PowerShell helper embedded in the runner: it registers/repairs the Windows
// service, so it is a build dependency and an edit must invalidate the cache.
const RUNNER_HELPER_PATH = process.env.MSI_RUNNER_HELPER || path.join(__dirname, '..', '..', 'scripts', 'agent-service-install.ps1');
const BUILD_SCRIPT = process.env.MSI_BUILD_SCRIPT || path.join(__dirname, '..', '..', 'scripts', 'build_msi.py');
const INSTALLERS_DIR = process.env.INSTALLERS_DIR || path.join(__dirname, '..', '..', 'installers');
const AGENT_EXE_DIR = process.env.AGENT_EXE_DIR || path.join(__dirname, '..', 'agents');
const MSI_VERSION = process.env.MSI_VERSION || '1.0.0';

const MSI_FILENAME = 'exagent-setup.msi';
// Every name inside the package is derived from the device group name, so a
// cached MSI is only reusable for the exact inputs it was built from. mtimes
// alone cannot see a rename (the build inputs are unchanged, only the value
// passed to the build script is), which shipped an "Exagent1999" package for
// a group that had already been renamed. The stamp is the content check.
const STAMP_FILENAME = 'agent-msi.inputs.json';

// The Windows x64 agent (MeshCentral id 4), cached per mesh id - the same cache
// builder.js uses. The mesh id lives in the .msh block MeshCentral appends to
// the executable, so the cache layer refuses to reuse an agent bound to a
// different mesh and refuses a download the server did not really serve
// (a deleted device group answers with a short "Unauthorized" body).
async function cachedAgentFor(meshUrl, meshid) {
  const agent = await resolveAgent(meshUrl, meshid);
  return agent.path;
}

function msiPathFor(clientName) {
  return path.join(INSTALLERS_DIR, safeDirName(clientName), MSI_FILENAME);
}

function stampPathFor(outPath) {
  return path.join(path.dirname(outPath), 'build', STAMP_FILENAME);
}

/** The exact values the package metadata is built from. */
function buildStamp(input) {
  return {
    client: String(input.clientName),
    meshid: String(input.meshid),
    server: String(input.publicUrl || ''),
    version: String(input.version),
    agentSha256: sha256File(input.agentPath),
  };
}

function readStamp(outPath) {
  try {
    return JSON.parse(fs.readFileSync(stampPathFor(outPath), 'utf8'));
  } catch (err) {
    return null;
  }
}

function writeStamp(outPath, stamp) {
  try {
    fs.mkdirSync(path.dirname(stampPathFor(outPath)), { recursive: true });
    fs.writeFileSync(stampPathFor(outPath), JSON.stringify(stamp, null, 2) + '\n');
  } catch (err) {
    // A missing stamp only costs a rebuild next time.
    console.error('[msi] could not write build stamp: ' + err.message);
  }
}

/**
 * A cached MSI is only valid while everything it is built from is older: the
 * WiX template, the NSIS runner template and the agent binary it embeds.
 * Its build stamp must also still describe the same group, mesh, server and
 * version - that is what makes a rename or a mesh rebind rebuild instead of
 * serving a package named after the old group.
 */
function cacheIsFresh(outPath, deps, expectedStamp) {
  if (!fs.existsSync(outPath) || fs.statSync(outPath).size < 1024) return false;
  const built = fs.statSync(outPath).mtimeMs;
  for (const dep of deps) {
    if (fs.existsSync(dep) && fs.statSync(dep).mtimeMs > built) return false;
  }
  const stamp = readStamp(outPath);
  if (!stamp) return false;
  for (const key of Object.keys(expectedStamp)) {
    if (String(stamp[key]) !== String(expectedStamp[key])) return false;
  }
  return true;
}

/**
 * Drop the cached MSI (and its stamp) for one group name, e.g. after a rename.
 * Only the files are removed - the directory also holds the group's .exe
 * installer, so it must never be deleted wholesale.
 */
function discardMsi(clientName) {
  const outPath = msiPathFor(clientName);
  for (const file of [outPath, stampPathFor(outPath)]) {
    try {
      fs.rmSync(file, { force: true });
    } catch (err) {
      console.error('[msi] could not remove ' + file + ': ' + err.message);
    }
  }
  return outPath;
}

/**
 * Build exagent-setup.msi for one device group.
 * Returns { filename, path, size, sha256, buildLog, cached }.
 */
async function buildMsi({ meshUrl, clientName, meshid, publicUrl, force = false }) {
  // meshUrl is used to download the agent (may be a loopback endpoint);
  // publicUrl is baked into the package metadata that admins will read.
  const serverUrl = publicUrl || meshUrl;
  if (!fs.existsSync(TEMPLATE_PATH)) {
    throw new Error('MSI template not found: ' + TEMPLATE_PATH);
  }
  if (!fs.existsSync(BUILD_SCRIPT)) {
    throw new Error('MSI build script not found: ' + BUILD_SCRIPT);
  }

  const outPath = msiPathFor(clientName);
  // Throws when MeshCentral has no such device group, instead of building an
  // installer whose agent can never enroll.
  const agentExe = await cachedAgentFor(meshUrl, meshid);
  const stamp = buildStamp({ clientName, meshid, publicUrl: serverUrl, version: MSI_VERSION, agentPath: agentExe });

  if (!force && cacheIsFresh(outPath, [TEMPLATE_PATH, RUNNER_TEMPLATE_PATH, RUNNER_HELPER_PATH, BUILD_SCRIPT, agentExe], stamp)) {
    return {
      filename: MSI_FILENAME,
      path: outPath,
      size: fs.statSync(outPath).size,
      sha256: sha256File(outPath),
      buildLog: 'cached build reused (template and agent unchanged)',
      cached: true,
    };
  }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  // build_msi.py compiles the console-less NSIS runner, renders the template,
  // runs the WiX compiler (wixl, or candle+light on Windows) and rejects a
  // build in which wixl silently dropped
  // elements it did not understand.
  const args = [
    BUILD_SCRIPT,
    '--agent', agentExe,
    '--client', String(clientName),
    '--meshid', String(meshid),
    '--server', String(serverUrl),
    '--out', outPath,
    '--version', MSI_VERSION,
    '--runner-helper', RUNNER_HELPER_PATH,
  ];

  let buildLog;
  try {
    const result = await execFileAsync(PYTHON, args, { maxBuffer: 10 * 1024 * 1024, timeout: 180000 });
    buildLog = (result.stdout || '') + (result.stderr || '');
  } catch (err) {
    const output = [err.stdout, err.stderr, err.message].filter(Boolean).join('\n');
    const e = new Error('installer build failed for client "' + clientName + '":\n' + output);
    e.buildOutput = output;
    throw e;
  }

  if (!fs.existsSync(outPath) || fs.statSync(outPath).size < 1024) {
    const e = new Error('MSI build did not produce ' + outPath + '\n' + buildLog);
    e.buildOutput = buildLog;
    throw e;
  }

  writeStamp(outPath, stamp);

  return {
    filename: MSI_FILENAME,
    path: outPath,
    size: fs.statSync(outPath).size,
    sha256: sha256File(outPath),
    buildLog,
    cached: false,
  };
}

module.exports = { buildMsi, msiPathFor, discardMsi, MSI_FILENAME, MSI_VERSION, INSTALLERS_DIR };
