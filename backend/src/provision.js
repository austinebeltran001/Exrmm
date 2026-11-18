// EX SOFTWARE LLC portal - MeshCentral provisioning layer.
//
// Every account that signs up on the portal gets a real MeshCentral account, so
// they can log into the rebranded console, build agents, create their own device
// groups and manage their own settings. The portal never stores passwords: it
// uses the MeshCentral administrator account (MESH_USER) over the control
// channel to create/rename/lock/delete accounts and to create, share, rename and
// delete device groups, while end-user authentication always happens against
// MeshCentral itself.
//
// Command contracts below were verified against the live server
// (MeshCentral 1.2.6) - see scripts/probe_mc_contracts.js and
// scripts/probe_mc_nodes.js:
//
//   login           POST /login                      -> session cookie
//   adduser         {username,pass,email,realname,emailVerified} -> {result:'ok'}
//   deleteuser      {userid}                         -> {result:'ok'}
//   edituser        {userid,realname,siteadmin,emailVerified}    -> {result:'ok'}
//   changeuserpass  {userid,pass,removeMultiFactor}   -> no reply (verified by login)
//   changepassword  {oldpass,newpass}                 -> no reply (self-service)
//   createmesh      {meshname,meshtype:2,desc}        -> {result:'ok',meshid,links}
//   editmesh        {meshid,meshname,desc}            -> {result:'ok'}
//   deletemesh      {meshid}                          -> {result:'ok'}
//   addmeshuser     {meshid,meshadmin,userids:[...]}  -> {result:'Added user x',success:1}
//   removemeshuser  {meshid,userid}                   -> {result:'ok'}
//   meshes                                            -> {meshes:[{_id,name,mtype,links,creatorid}]}
//   nodes           {meshid}                          -> {nodes:{'<meshid>':[node,...]}}
//   users                                             -> {users:[...]}
//
// MeshCentral domain id is empty (''), so user ids look like 'user//<email>' and
// mesh ids look like 'mesh//<base64>'.

'use strict';

const meshclient = require('./meshclient');

const MESH_URL = (process.env.MESH_URL || 'https://remote.exrmm.com').replace(/\/+$/, '');
const MESH_USER = process.env.MESH_USER;
const MESH_PASS = process.env.MESH_PASS;
const MESH_DOMAIN = process.env.MESH_DOMAIN || '';

const RIGHTS_FULL = 4294967295;      // full rights on a single device group
const SITERIGHT_ADMIN = 0xFFFFFFFF;
const SITERIGHT_ACCOUNT_LOCKED = 32; // siteadmin bit 32
const GROUP_DESC = 'Created with EX SOFTWARE LLC';

// ---------------------------------------------------------------
// Admin control channel with a cached, re-usable session cookie
// ---------------------------------------------------------------
let adminSession = null;
const SESSION_TTL_MS = 4 * 60 * 1000;

async function getAdminCookie(force) {
  if (!force && adminSession && Date.now() - adminSession.at < SESSION_TTL_MS) {
    return adminSession.cookie;
  }
  const res = await meshclient.login(MESH_URL, MESH_USER, MESH_PASS);
  adminSession = { cookie: res.cookie, at: Date.now() };
  return adminSession.cookie;
}

/**
 * Run one administrator command. On a transport failure (stale WebSocket or an
 * expired session cookie) the admin session is refreshed once and the command
 * is retried.
 */
async function run(command, retry = true) {
  try {
    const cookie = await getAdminCookie();
    return await meshclient.controlCommand(MESH_URL, cookie, command);
  } catch (err) {
    // Covers both a stale/expired admin session and a transport failure: drop
    // the cached session, obtain a fresh one and try exactly once more.
    if (!retry) throw consoleUnavailable(err);
    adminSession = null;
    return run(command, false);
  }
}

/**
 * Wrap a MeshCentral transport/session failure so the API layer can answer with
 * a "console temporarily unavailable" (503) instead of a credentials error.
 */
function consoleUnavailable(err) {
  const out = new Error('The management console could not complete the request: ' + err.message);
  out.code = 'console_unavailable';
  out.statusCode = 503;
  out.mcCode = err.code || null;
  return out;
}

/**
 * MeshCentral signals application-level failures with `result` set to the error
 * text instead of 'ok'. Some successful replies carry informational text
 * ('Added user ...'), so callers pass the expected shape.
 */
function unwrap(resp, action, okWhen) {
  if (okWhen(resp)) return resp;
  const detail = resp && resp.result != null ? resp.result : JSON.stringify(resp);
  const err = new Error('MeshCentral ' + action + ' failed: ' + detail);
  err.mcResult = detail;
  throw err;
}

function expectOk(resp, action) {
  return unwrap(resp, action, (r) => r && (r.result === 'ok' || r.result === true || r.success === 1));
}

function useridFor(email) {
  const needle = String(email || '').trim().toLowerCase();
  if (!needle) throw new Error('email is required');
  return 'user/' + MESH_DOMAIN + '/' + needle;
}

function meshidFor(meshid) {
  if (typeof meshid !== 'string' || meshid.length === 0) throw new Error('meshid is required');
  return meshid.indexOf('/') === -1 ? 'mesh/' + MESH_DOMAIN + '/' + meshid : meshid;
}

// ---------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------
/**
 * Create the MeshCentral account for a portal user. The email address doubles
 * as the MeshCentral user name (the server runs with UserNameIsEmail), and the
 * email is created pre-verified so the user can sign in with the password they
 * chose during sign-up and can create device groups without first having to
 * confirm a mailbox.
 */
async function createAccount({ email, name, password }) {
  const username = String(email).trim().toLowerCase();
  const resp = await run({
    action: 'adduser',
    username,
    pass: password,
    email: username,
    realname: name || username,
    emailVerified: true,
  });
  if (resp && resp.result === 'ok') {
    return { mcUserid: useridFor(username), email: username };
  }
  const detail = resp && resp.result != null ? resp.result : JSON.stringify(resp);
  const err = new Error(detail);
  err.mcResult = detail;
  if (/already exists/i.test(detail)) err.code = 'account_exists';
  throw err;
}

async function deleteAccount(mcUserid) {
  const resp = await run({ action: 'deleteuser', userid: mcUserid });
  if (resp && /does not exists/i.test(String(resp.result))) return { alreadyGone: true };
  return expectOk(resp, 'deleteuser');
}

async function setRealName(mcUserid, realname) {
  return expectOk(await run({ action: 'edituser', userid: mcUserid, realname: realname || '' }), 'edituser');
}

/**
 * Set an account password as the administrator (used by the portal's
 * self-service and forgot-password flows). changeuserpass sends no reply, so
 * callers should confirm the result by calling verifyCredentials().
 */
async function setPassword(mcUserid, password) {
  const cookie = await getAdminCookie();
  await meshclient.controlCommandNoReply(MESH_URL, cookie, {
    action: 'changeuserpass',
    userid: mcUserid,
    pass: password,
    removeMultiFactor: false,
  });
  return { ok: true };
}

/** Lock / unlock an account at the MeshCentral level (siteadmin bit 32). */
async function setAccountLocked(mcUserid, locked) {
  const account = await getAccount(mcUserid);
  const current = typeof account.siteadmin === 'number' ? account.siteadmin : 0;
  const next = locked ? (current | SITERIGHT_ACCOUNT_LOCKED) : (current & ~SITERIGHT_ACCOUNT_LOCKED);
  if (next === current) return { siteadmin: current, changed: false };
  const resp = await run({ action: 'edituser', userid: mcUserid, siteadmin: next });
  return { siteadmin: next, changed: true, result: resp && resp.result };
}

/** Look up one account (used to read siteadmin bits). */
async function getAccount(mcUserid) {
  const users = await listAccounts();
  const found = users.find((u) => u._id === mcUserid);
  if (!found) return null;
  return found;
}

async function listAccounts() {
  const resp = await run({ action: 'users' });
  if (Array.isArray(resp.users)) return resp.users;
  if (resp.users && typeof resp.users === 'object') return Object.values(resp.users);
  return [];
}

/**
 * Log in as an end user and prove the session is really authenticated.
 *
 * MeshCentral's POST /login answers HTTP 200 with an xid cookie even when the
 * credentials are wrong or the account is locked, so a Set-Cookie header is NOT
 * proof of authentication. The only reliable check is to open the control
 * channel with that cookie and ask for the account identity (userinfo).
 */
async function loginAsUser(email, password) {
  const username = String(email).trim().toLowerCase();
  const { cookie } = await meshclient.login(MESH_URL, username, password);
  const info = await meshclient.controlCommand(MESH_URL, cookie, { action: 'userinfo' }, 15000);
  const userinfo = info && info.userinfo;
  if (!userinfo || !userinfo._id) {
    const err = new Error('MeshCentral session is not authenticated');
    err.code = 'not_authenticated';
    throw err;
  }
  if (userinfo._id !== useridFor(username)) {
    const err = new Error('MeshCentral session identity mismatch');
    err.code = 'identity_mismatch';
    throw err;
  }
  return { cookie, userinfo };
}

/** Confirm an account really can authenticate with the given password. */
async function verifyCredentials(email, password) {
  try {
    await loginAsUser(email, password);
    return true;
  } catch (err) {
    // A rejected MeshCentral login is the only outcome that means "these
    // credentials are wrong" (or the account is locked / the address is
    // throttled - MeshCentral does not distinguish those in the response).
    // Anything else is an infrastructure failure and must NOT be reported to
    // the user as a wrong password.
    if (err.code === 'not_authenticated' || err.code === 'identity_mismatch') return false;
    throw consoleUnavailable(err);
  }
}

// ---------------------------------------------------------------
// Device groups (meshes)
// ---------------------------------------------------------------
/**
 * Create an Agent device group owned by the portal administrator and share it
 * with the portal user with full rights on that group. MeshCentral records the
 * creating account as the group owner; the portal therefore tracks ownership in
 * its own database and lists groups per user from the group's `links` map.
 */
async function createDeviceGroup({ name, description, ownerMcUserid }) {
  const resp = await run({
    action: 'createmesh',
    meshname: name,
    meshtype: 2, // Agent mesh
    desc: description || GROUP_DESC,
  });
  expectOk(resp, 'createmesh');
  if (!resp.meshid) throw new Error('MeshCentral createmesh returned no meshid');

  if (ownerMcUserid) await shareDeviceGroup(resp.meshid, ownerMcUserid);
  return { meshid: resp.meshid, name };
}

async function shareDeviceGroup(meshid, mcUserid, rights = RIGHTS_FULL) {
  const resp = await run({
    action: 'addmeshuser',
    meshid: meshidFor(meshid),
    meshadmin: rights,
    userids: [mcUserid],
  });
  return unwrap(resp, 'addmeshuser', (r) => r && (r.success === 1 || /^Added user/i.test(String(r.result))));
}

async function unshareDeviceGroup(meshid, mcUserid) {
  const resp = await run({ action: 'removemeshuser', meshid: meshidFor(meshid), userid: mcUserid });
  if (resp && /not in group/i.test(String(resp.result))) return { removed: false };
  expectOk(resp, 'removemeshuser');
  return { removed: true };
}

async function renameDeviceGroup(meshid, name, description) {
  const command = { action: 'editmesh', meshid: meshidFor(meshid) };
  if (name) command.meshname = name;
  if (description != null) command.desc = description;
  return expectOk(await run(command), 'editmesh');
}

async function deleteDeviceGroup(meshid) {
  const resp = await run({ action: 'deletemesh', meshid: meshidFor(meshid) });
  if (resp && /unknown device group/i.test(String(resp.result))) return { alreadyGone: true };
  return expectOk(resp, 'deletemesh');
}

/** All agent device groups in the domain, including their links map. */
async function listDeviceGroups() {
  const resp = await run({ action: 'meshes' });
  const list = Array.isArray(resp.meshes) ? resp.meshes : [];
  return list.filter((m) => m && m.mtype === 2 && m.deleted == null);
}

/** Agent device groups a MeshCentral account has rights to. */
async function listDeviceGroupsForUser(mcUserid) {
  const all = await listDeviceGroups();
  return all.filter((m) => m.links && m.links[mcUserid]);
}

// ---------------------------------------------------------------
// Devices
// ---------------------------------------------------------------
function flattenNodes(resp) {
  const out = [];
  const nodes = resp && resp.nodes;
  if (!nodes) return out;
  for (const key of Object.keys(nodes)) {
    const value = nodes[key];
    if (Array.isArray(value)) {
      for (const n of value) if (n) out.push(n);
    } else if (value && typeof value === 'object') {
      out.push(value);
    }
  }
  return out;
}

async function listNodes(meshid) {
  const resp = await run({ action: 'nodes', meshid: meshidFor(meshid) });
  return flattenNodes(resp);
}

/** Devices across every device group the given account can see. */
async function listDevicesForUser(mcUserid) {
  const groups = await listDeviceGroupsForUser(mcUserid);
  const devices = [];
  for (const group of groups) {
    let nodes = [];
    try {
      nodes = await listNodes(group._id);
    } catch (err) {
      nodes = [];
    }
    for (const n of nodes) {
      devices.push({
        id: n._id,
        name: n.name || n.rname || 'Unnamed device',
        group_id: group._id,
        group_name: group.name,
        os: n.osdesc || null,
        ip: n.ip || n.host || null,
        // node.conn is a connectivity bitmask: 1 = agent, 2 = CIRA, 4 = AMT.
        online: (Number(n.conn) & 1) === 1,
        last_connect: n.lastconnecttime ? new Date(n.lastconnecttime).toISOString() : null,
        agent_version: n.agent && n.agent.ver ? n.agent.ver : null,
      });
    }
  }
  return devices;
}

/**
 * Download the branded Windows x64 agent for a device group. Delegates to the
 * MeshCentral meshagents endpoint which bakes in the server URL and mesh id.
 */
async function downloadAgent(meshid, destPath) {
  return meshclient.downloadAgent(MESH_URL, meshidFor(meshid), destPath);
}

module.exports = {
  MESH_URL,
  MESH_DOMAIN,
  RIGHTS_FULL,
  SITERIGHT_ACCOUNT_LOCKED,
  getAdminCookie,
  run,
  useridFor,
  meshidFor,
  createAccount,
  deleteAccount,
  setRealName,
  setPassword,
  setAccountLocked,
  getAccount,
  listAccounts,
  verifyCredentials,
  loginAsUser,
  createDeviceGroup,
  shareDeviceGroup,
  unshareDeviceGroup,
  renameDeviceGroup,
  deleteDeviceGroup,
  listDeviceGroups,
  listDeviceGroupsForUser,
  listNodes,
  listDevicesForUser,
  downloadAgent,
};
