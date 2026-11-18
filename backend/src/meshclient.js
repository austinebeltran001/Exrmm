// EX SOFTWARE LLC portal - MeshCentral control-channel client.
//
// MeshCentral exposes account-scoped actions (e.g. createmesh) over a
// WebSocket at wss://<host>/control.ashx, authenticated with the HTTP
// session cookie obtained from POST /login. This module wraps that flow:
//
//   1. login()          -> POST /login (form encoded), collect cookies
//   2. controlCommand() -> open WSS control.ashx with the cookie and
//                          exchange a single command/response pair
//
// TLS verification is disabled on purpose: MeshCentral uses a
// self-signed certificate internally and the deployment sits behind a
// reverse proxy. NODE_TLS_REJECT_UNAUTHORIZED='0' is set in server.js.

'use strict';

const https = require('https');
const crypto = require('crypto');
const WebSocket = require('ws');

const MESH_AGENT_TYPE_WINDOWS_64 = 4; // MeshService64 - Windows x64

/**
 * Decode the MeshCentral session cookie ('xid') into its payload.
 *
 * MeshCentral only writes a `userid` into that payload once the password was
 * accepted; a session that failed authentication (wrong password, locked
 * account, or throttle-blocked login) carries an empty object. Anything that
 * treats "MeshCentral answered with a cookie" as "user is authenticated" is
 * therefore wrong - the payload has to be checked.
 */
function decodeXid(cookie) {
  const match = /(?:^|;\s*)xid=([^;]+)/.exec(String(cookie || ''));
  if (!match) return null;
  try {
    return JSON.parse(Buffer.from(match[1], 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

/**
 * POST /login with form encoded credentials.
 *
 * Resolves only when MeshCentral actually authenticated the caller (the xid
 * cookie carries a userid), with { statusCode, cookie, body, authenticated,
 * userid }. A rejected login rejects with err.code = 'not_authenticated' and
 * err.mcLogin describing the raw response, so callers can tell "these
 * credentials are wrong / the login was throttled" apart from a transport
 * failure (thrown as-is).
 */
function login(baseUrl, username, password) {
  const u = new URL(baseUrl);
  const body = new URLSearchParams({ username, password }).toString();

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname.replace(/\/+$/, '') + '/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'EXagentPortal/1.0',
        },
        rejectUnauthorized: false, // MeshCentral uses a self-signed cert internally
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const setCookies = res.headers['set-cookie'] || [];
          const cookie = setCookies.map((c) => c.split(';')[0]).join('; ');
          const session = decodeXid(cookie) || {};
          const result = {
            statusCode: res.statusCode,
            cookie,
            body: Buffer.concat(chunks).toString('utf8'),
            authenticated: typeof session.userid === 'string' && session.userid.length > 0,
            userid: session.userid || null,
          };
          if (!result.authenticated) {
            const err = new Error(
              'MeshCentral refused the login for ' + username +
              ' (wrong password, locked account, or login throttling for this address)'
            );
            err.code = 'not_authenticated';
            err.statusCode = 401;
            err.mcLogin = { statusCode: result.statusCode, authenticated: false, userid: null };
            return reject(err);
          }
          resolve(result);
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('MeshCentral login timed out')));
    req.write(body);
    req.end();
  });
}

/**
 * Send one command over wss://<host>/control.ashx and resolve with the
 * matching response (matched by responseid).
 */
function controlCommand(baseUrl, cookie, command, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const u = new URL(baseUrl);
    u.protocol = u.protocol === 'http:' ? 'ws:' : 'wss:';
    u.pathname = u.pathname.replace(/\/+$/, '') + '/control.ashx';

    const responseid = 'htp_' + crypto.randomBytes(8).toString('hex');
    const payload = JSON.stringify(Object.assign({}, command, { responseid }));

    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws.close(); } catch (e) { /* ignore */ }
      fn(arg);
    };

    const timer = setTimeout(() => finish(reject, new Error('MeshCentral control channel timed out')), timeoutMs);

    const ws = new WebSocket(u.href, {
      rejectUnauthorized: false, // self-signed internal cert
      headers: { Cookie: cookie },
    });

    ws.on('open', () => ws.send(payload));

    ws.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString('utf8')); } catch (e) { return; }
      // MeshCentral echoes responseid for most commands, but some (e.g. the
      // 'meshes' listing) reply without it; fall back to matching by action.
      // NOTE: 'result' on some successful commands is informational text
      // (e.g. addmeshuser -> 'Added user <id>'), so the raw response is
      // always resolved and CALLERS validate the outcome.
      if (msg.responseid === responseid || (!msg.responseid && msg.action === command.action)) {
        finish(resolve, msg);
      }
    });

    ws.on('error', (err) => finish(reject, err));
    ws.on('close', (code, reason) => finish(reject, new Error('WebSocket closed before response (code ' + code + ' ' + reason + ')')));
  });
}

/**
 * Send one command over the control channel WITHOUT waiting for an application
 * reply. Some MeshCentral commands (changeuserpass) deliberately never answer,
 * so waiting would stall until the timeout. The socket is held open for
 * settleMs so the server can process the message, then closed.
 *
 * Callers must verify the effect separately (e.g. by logging in again).
 */
function controlCommandNoReply(baseUrl, cookie, command, settleMs = 1000, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const u = new URL(baseUrl);
    u.protocol = u.protocol === 'http:' ? 'ws:' : 'wss:';
    u.pathname = u.pathname.replace(/\/+$/, '') + '/control.ashx';

    const payload = JSON.stringify(Object.assign({}, command));
    let settled = false;
    let sent = false;
    let settleTimer = null;

    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (settleTimer) clearTimeout(settleTimer);
      try { ws.close(); } catch (e) { /* ignore */ }
      fn(arg);
    };

    const timer = setTimeout(() => finish(reject, new Error('MeshCentral control channel timed out')), timeoutMs);

    const ws = new WebSocket(u.href, { rejectUnauthorized: false, headers: { Cookie: cookie } });

    ws.on('open', () => {
      sent = true;
      ws.send(payload);
      settleTimer = setTimeout(() => finish(resolve, { sent: true, noReply: true }), settleMs);
    });

    ws.on('error', (err) => finish(reject, err));
    ws.on('close', (code, reason) => {
      if (sent && !settled) return finish(resolve, { sent: true, noReply: true });
      finish(reject, new Error('WebSocket closed before send (code ' + code + ' ' + reason + ')'));
    });
  });
}

/**
 * High level helpers used by the portal API.
 */
async function createDeviceGroup(baseUrl, username, password, groupName, description) {
  const { cookie } = await login(baseUrl, username, password);
  const resp = await controlCommand(baseUrl, cookie, {
    action: 'createmesh',
    meshname: groupName,
    meshtype: 2, // Agent mesh
    desc: description || 'EX SOFTWARE LLC client device group',
  });
  if (!resp.meshid) throw new Error('MeshCentral did not return a mesh id: ' + JSON.stringify(resp));
  return { meshid: resp.meshid, name: groupName };
}

async function listDeviceGroups(baseUrl, username, password) {
  const { cookie } = await login(baseUrl, username, password);
  const resp = await controlCommand(baseUrl, cookie, { action: 'meshes' });
  return resp.meshes || [];
}

async function deleteDeviceGroup(baseUrl, username, password, meshid) {
  const { cookie } = await login(baseUrl, username, password);
  const resp = await controlCommand(baseUrl, cookie, { action: 'deletemesh', meshid });
  return resp;
}

/**
 * Download the Windows x64 agent binary for a device group.
 * The returned binary has the server URL and mesh id baked in.
 */
async function downloadAgent(baseUrl, meshid, destPath) {
  const u = new URL(baseUrl);
  // /meshagents expects ONLY the base64 segment of the full mesh id
  // ('mesh/<domain>/<base64>'); it reassembles 'mesh/' + domain + '/' + part
  // internally and returns 401 when the full id is passed.
  const meshIdPart = String(meshid).split('/')[2] || meshid;
  const path = u.pathname.replace(/\/+$/, '') + '/meshagents?id=' + MESH_AGENT_TYPE_WINDOWS_64 + '&meshid=' + encodeURIComponent(meshIdPart);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path,
        method: 'GET',
        headers: { 'User-Agent': 'EXagentPortal/1.0' },
        rejectUnauthorized: false,
      },
      (res) => {
        if (res.statusCode !== 200) {
          return reject(new Error('Agent download failed: HTTP ' + res.statusCode));
        }
        const fs = require('fs');
        const out = fs.createWriteStream(destPath);
        res.pipe(out);
        out.on('finish', () => out.close(() => resolve(destPath)));
        out.on('error', reject);
      }
    );
    req.on('error', reject);
    req.setTimeout(120000, () => req.destroy(new Error('Agent download timed out')));
    req.end();
  });
}

module.exports = { login, decodeXid, controlCommand, controlCommandNoReply, createDeviceGroup, listDeviceGroups, deleteDeviceGroup, downloadAgent, MESH_AGENT_TYPE_WINDOWS_64 };
