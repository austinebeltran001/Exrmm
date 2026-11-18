// EX SOFTWARE LLC portal - external build-tool discovery.
//
// The portal shells out to three tools that live outside %PATH% on the Windows
// build hosts (and on the VPS are installed system-wide):
//
//   makensis   NSIS        C:\Program Files (x86)\NSIS\makensis.exe
//   candle/light  WiX v3   C:\exrmm\wix\
//   python     interpreter for scripts/build_msi.py
//
// Executing a bare program name makes Node let Windows resolve it through the
// PATH the portal process inherited at start-up. That PATH is whatever the
// start-up task had, and it is not updated when a tool is installed later - so
// a download failed with "spawn makensis ENOENT" on a host where NSIS was
// installed and working. The same request also reported "no WiX compiler found"
// for the MSI until the Python script learned to look in C:\exrmm\wix.
//
// This module resolves each tool to an absolute path and prepends the known
// install directories to process.env.PATH, so children of children (python
// spawning makensis for the WiX runner) inherit a usable PATH too.
// Overrides: NSIS_EXE / MAKENSIS_EXE, WIX_BIN, PYTHON.

'use strict';

const fs = require('fs');
const path = require('path');

const IS_WINDOWS = process.platform === 'win32';

const EXTRA_DIRS = [
  process.env.NSIS_DIR || '',
  process.env.WIX_BIN || '',
  process.env.WIX_DIR || '',
  'C:\\exrmm\\nsis',
  'C:\\exrmm\\wix',
  'C:\\Program Files (x86)\\NSIS',
  'C:\\Program Files\\NSIS',
  'C:\\Program Files (x86)\\WiX Toolset v3.14\\bin',
  'C:\\Program Files (x86)\\WiX Toolset v3.11\\bin',
];

function isFile(candidate) {
  try {
    return !!candidate && fs.statSync(candidate).isFile();
  } catch (err) {
    return false;
  }
}

// Search the current PATH the way the shell would, so an already-working
// installation keeps precedence over the hard-coded fallbacks below.
function fromPath(names) {
  const dirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  for (const name of names) {
    for (const dir of dirs) {
      const candidate = path.join(dir, name);
      if (isFile(candidate)) return candidate;
    }
  }
  return null;
}

function searchDirs(names) {
  for (const name of names) {
    for (const dir of EXTRA_DIRS) {
      if (!dir) continue;
      const candidate = path.join(dir, name);
      if (isFile(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Absolute path of makensis.exe, or the bare name when nothing is found (so
 * the caller still gets a recognisable "spawn makensis ENOENT" instead of an
 * obscure failure).
 */
function resolveMakensis() {
  const override = process.env.MAKENSIS_EXE || process.env.NSIS_EXE;
  if (override && isFile(override)) return override;
  const names = IS_WINDOWS ? ['makensis.exe', 'makensis'] : ['makensis'];
  return fromPath(names) || searchDirs(names) || 'makensis';
}

/**
 * Absolute path of the Python interpreter used for scripts/build_msi.py.
 * Windows has python.exe, Linux ships python3.
 */
function resolvePython() {
  const override = process.env.PYTHON;
  if (override && isFile(override)) return override;
  const names = IS_WINDOWS ? ['python.exe', 'python3.exe'] : ['python3', 'python'];
  return fromPath(names) || searchDirs(names) || (IS_WINDOWS ? 'python' : 'python3');
}

/**
 * Prepend the known tool directories to this process's PATH so that every
 * child process - including scripts that spawn their own children - can find
 * the tools. Idempotent.
 */
function seedPath() {
  const parts = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const extra = [];
  for (const dir of EXTRA_DIRS) {
    if (!dir) continue;
    if (!fs.existsSync(dir)) continue;
    if (parts.includes(dir) || extra.includes(dir)) continue;
    extra.push(dir);
  }
  if (extra.length) {
    process.env.PATH = extra.concat(parts).join(path.delimiter);
  }
  return extra;
}

seedPath();

module.exports = { resolveMakensis, resolvePython, seedPath, EXTRA_DIRS };
