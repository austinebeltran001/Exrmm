// EX SOFTWARE LLC portal - NSIS installer builder.
//
// For a client device group this module:
//   1. downloads the MeshCentral Windows x64 agent (meshid baked in)
//   2. saves it as exagent-agent.exe
//   3. renders scripts/installer-template.nsi with client parameters
//   4. runs makensis to produce installers/<client>/exagent-setup.exe
//
// Every name inside the package (Add/Remove Programs entry, Program Files
// folder, service name, service display name, registry key) is derived from the
// device group name by scripts/build_msi.py, which is asked for them with
// --print-names. That keeps the .exe and the .msi identical in naming and
// avoids a second, drifting copy of the derivation rules in JavaScript.
//
// On any NSIS failure the FULL makensis output is attached to the thrown
// error so the caller can report it verbatim.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
// Both tools are resolved to absolute paths and the known install directories
// are prepended to PATH (see toolchain.js). Spawning a bare 'makensis' made
// Windows search the PATH this process inherited at start-up, which does not
// contain NSIS, so every .exe download failed with 'spawn makensis ENOENT'.
const { resolveMakensis, resolvePython } = require('./toolchain');
// Windows has python.exe, Linux ships python3. Resolve the interpreter per
// platform (PYTHON overrides it, e.g. for a portable/virtualenv install).
const PYTHON = resolvePython();
const { resolveAgent } = require('./agentcache');

const TEMPLATE_PATH = process.env.NSIS_TEMPLATE || path.join(__dirname, '..', '..', 'scripts', 'installer-template.nsi');
const BUILD_SCRIPT = process.env.MSI_BUILD_SCRIPT || path.join(__dirname, '..', '..', 'scripts', 'build_msi.py');
const HELPER_PATH = process.env.MSI_RUNNER_HELPER || path.join(__dirname, '..', '..', 'scripts', 'agent-service-install.ps1');
const INSTALLERS_DIR = process.env.INSTALLERS_DIR || path.join(__dirname, '..', '..', 'installers');
const AGENT_EXE_DIR = process.env.AGENT_EXE_DIR || path.join(__dirname, '..', 'agents');
const NSIS_VERSION = process.env.NSIS_VERSION || '1.0.1.0';

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// NSIS treats '$' as a variable sigil ('$d', '$x', '${...}') and a bare '"'
// closes the string being built, so a substituted value must escape both.
// MeshCentral mesh ids are base64 with '@' and '$' standing in for '+' and '/',
// so the '$' half is not optional: an unescaped mesh id compiles into a
// silently corrupted value.
function nsiEscape(value) {
  return String(value).replace(/\$/g, () => '$$').replace(/"/g, () => '$\\"');
}

function safeDirName(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'client';
}

/**
 * Ask the MSI build script for the canonical names of one device group.
 * --print-names validates nothing and touches nothing; it only prints JSON, so
 * the agent/mesh/server arguments are only there to satisfy the CLI.
 */
async function derivedNames({ clientName, meshid, serverUrl }) {
  const args = [
    BUILD_SCRIPT,
    '--agent', 'unused',
    '--client', String(clientName),
    '--meshid', String(meshid),
    '--server', String(serverUrl),
    '--out', 'unused',
    '--print-names',
  ];
  let stdout;
  try {
    const result = await execFileAsync(PYTHON, args, { maxBuffer: 1024 * 1024, timeout: 60000 });
    stdout = result.stdout;
  } catch (err) {
    const output = [err.stdout, err.stderr, err.message].filter(Boolean).join('\n');
    throw new Error('could not derive installer names for "' + clientName + '":\n' + output);
  }
  let names;
  try {
    names = JSON.parse(stdout);
  } catch (err) {
    throw new Error('build_msi.py --print-names returned no JSON for "' + clientName + '": ' + stdout);
  }
  for (const key of ['product_name', 'install_dir', 'service_name', 'service_display_name', 'reg_key', 'agent_filename']) {
    if (!names[key]) throw new Error('build_msi.py --print-names did not return ' + key + ' for "' + clientName + '"');
  }
  return names;
}

/**
 * Build exagent-setup.exe for one client device group.
 * Returns { filename, path, size, sha256, buildLog, names }.
 */
async function buildInstaller({ meshUrl, clientName, meshid, publicUrl }) {
  // meshUrl is the endpoint this server uses to talk to MeshCentral (it may be
  // a loopback address); publicUrl is what the installed agent and the
  // Add/Remove Programs metadata must advertise to the outside world.
  const serverUrl = publicUrl || meshUrl;
  const dirName = safeDirName(clientName);
  const clientDir = path.join(INSTALLERS_DIR, dirName);
  const buildDir = path.join(clientDir, 'build');
  fs.mkdirSync(buildDir, { recursive: true });
  fs.mkdirSync(AGENT_EXE_DIR, { recursive: true });

  // 1. Agent binary (cached per mesh id; the mesh id is baked into it). The
  //    cache layer rejects a cached binary whose .msh points at another (or a
  //    deleted) mesh, so a stale cache can no longer ship a dead binding.
  const agent = await resolveAgent(meshUrl, meshid);
  const agentExe = path.join(buildDir, 'exagent-agent.exe');
  fs.copyFileSync(agent.path, agentExe);

  // 2. Canonical per-group names.
  const names = await derivedNames({ clientName, meshid, serverUrl });
  const uninstallKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\EXagent_' + names.install_dir;

  // 3. Render the NSIS template.
  const template = fs.readFileSync(TEMPLATE_PATH, 'utf8');
  let nsi = template
    .split('{{OUTFILE}}').join(nsiEscape(path.join(clientDir, 'exagent-setup.exe')))
    .split('{{AGENT_EXE}}').join(nsiEscape(agentExe))
    .split('{{HELPER_PS1}}').join(nsiEscape(HELPER_PATH))
    .split('{{PRODUCT_NAME}}').join(nsiEscape(names.product_name))
    .split('{{PRODUCT_VERSION}}').join(nsiEscape(NSIS_VERSION))
    .split('{{INSTALL_DIR_NAME}}').join(nsiEscape(names.install_dir))
    .split('{{SERVICE_NAME}}').join(nsiEscape(names.service_name))
    .split('{{SERVICE_DISPLAY_NAME}}').join(nsiEscape(names.service_display_name))
    .split('{{REG_KEY}}').join(nsiEscape(names.reg_key))
    .split('{{UNINST_KEY}}').join(nsiEscape(uninstallKey))
    .split('{{AGENT_FILENAME}}').join(nsiEscape(names.agent_filename))
    .split('{{MESH_ID}}').join(nsiEscape(meshid))
    .split('{{SERVER_URL}}').join(nsiEscape(serverUrl));

  // A placeholder left behind would ship a literal "{{...}}" into the
  // installer instead of failing the build, so refuse to compile one.
  const leftover = nsi.match(/\{\{[A-Z0-9_]+\}\}/);
  if (leftover) {
    throw new Error('installer template placeholder not substituted: ' + leftover[0]);
  }
  // NSIS has no syntax highlighting of its own; a stray CRLF is harmless, but a
  // NUL byte would truncate the script.
  nsi = nsi.replace(/\u0000/g, '');

  const nsiPath = path.join(buildDir, 'installer.nsi');
  fs.writeFileSync(nsiPath, nsi);

  // 4. Compile with NSIS; surface the full compiler output on failure.
  let makensis;
  try {
    const result = await execFileAsync(resolveMakensis(), ['-V2', nsiPath], { maxBuffer: 10 * 1024 * 1024, timeout: 180000 });
    makensis = (result.stdout || '') + (result.stderr || '');
  } catch (err) {
    const output = [err.stdout, err.stderr, err.message].filter(Boolean).join('\n');
    const e = new Error('makensis failed for client "' + clientName + '":\n' + output);
    e.buildOutput = output;
    throw e;
  }

  // 5. Validate the produced installer.
  const outPath = path.join(clientDir, 'exagent-setup.exe');
  if (!fs.existsSync(outPath) || fs.statSync(outPath).size < 1024) {
    throw new Error('makensis did not produce ' + outPath + '\n' + makensis);
  }

  return {
    filename: 'exagent-setup.exe',
    path: outPath,
    size: fs.statSync(outPath).size,
    sha256: sha256File(outPath),
    buildLog: makensis,
    names,
  };
}

module.exports = { buildInstaller, safeDirName, sha256File, nsiEscape, derivedNames, INSTALLERS_DIR };
