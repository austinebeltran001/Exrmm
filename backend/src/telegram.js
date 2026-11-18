// EX SOFTWARE LLC portal - optional Telegram notifications.
//
// Two independent audiences:
//
//   1. Portal users  - their own bot token + chat id, notified when a device
//                      in one of THEIR device groups connects or disconnects.
//   2. Administrators - a single admin bot/chat that receives a feed of device
//                      transitions for every user, plus new-account and
//                      sign-in events.
//
// Everything is opt-in. A user who never configures Telegram is never
// contacted, and the watcher does not even poll their devices unless the admin
// feed needs them.
//
// Security notes
//   * Bot tokens are credentials. They are encrypted at rest (AES-256-GCM,
//     key derived from TELEGRAM_ENC_KEY or SESSION_SECRET) and are NEVER sent
//     back to the browser; the API returns only a hint (last 4 characters).
//   * Tokens are validated against a strict pattern before being placed in a
//     URL, so a crafted "token" cannot redirect the request to another host.
//   * Device names / group names / emails are HTML-escaped before being put
//     into a Telegram message (parse_mode=HTML).
//   * Telegram is best-effort: a failure is recorded on the row and never
//     breaks a portal request or the watcher.

'use strict';

const crypto = require('crypto');

const { authdb: db } = require('./authdb');
const provision = require('./provision');

const API_BASE = (process.env.TELEGRAM_API_BASE || 'https://api.telegram.org').replace(/\/+$/, '');
const API_TIMEOUT_MS = parseInt(process.env.TELEGRAM_TIMEOUT_MS || '10000', 10);
const POLL_SECONDS = Math.max(30, parseInt(process.env.TELEGRAM_POLL_SECONDS || '90', 10));
const MAX_EVENTS_PER_ADMIN_MESSAGE = 15;

// ---------------------------------------------------------------------------
// Schema (additive only)
// ---------------------------------------------------------------------------
db.exec(`
CREATE TABLE IF NOT EXISTS portal_telegram (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id            INTEGER NOT NULL UNIQUE REFERENCES portal_users(id) ON DELETE CASCADE,
  token_enc          TEXT    NOT NULL,
  chat_id            TEXT    NOT NULL,
  chat_label         TEXT,
  enabled            INTEGER NOT NULL DEFAULT 1,
  notify_connect     INTEGER NOT NULL DEFAULT 1,
  notify_disconnect  INTEGER NOT NULL DEFAULT 1,
  verified_at        TEXT,
  last_error         TEXT,
  last_sent_at       TEXT,
  created_at         TEXT    NOT NULL,
  updated_at         TEXT    NOT NULL
);

-- Last observed presence per (user, device). This is what turns a poll into a
-- connect/disconnect EDGE instead of a repeated "still online" message.
CREATE TABLE IF NOT EXISTS portal_device_state (
  user_id     INTEGER NOT NULL,
  device_id   TEXT    NOT NULL,
  name        TEXT,
  group_name  TEXT,
  online      INTEGER NOT NULL DEFAULT 0,
  changed_at  TEXT,
  updated_at  TEXT    NOT NULL,
  PRIMARY KEY (user_id, device_id)
);

-- Small key/value store used for the administrator's Telegram configuration.
CREATE TABLE IF NOT EXISTS portal_settings (
  key         TEXT PRIMARY KEY,
  value       TEXT,
  updated_at  TEXT
);
`);

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------
function encryptionKey() {
  const material = process.env.TELEGRAM_ENC_KEY || process.env.SESSION_SECRET || '';
  if (material.length < 16) {
    throw Object.assign(new Error('Telegram credentials cannot be stored: SESSION_SECRET is not configured.'), {
      statusCode: 500,
      code: 'no_encryption_key',
    });
  }
  return crypto.createHash('sha256').update('exrmm-telegram-v1|' + material).digest();
}

function encryptSecret(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', iv.toString('base64'), tag.toString('base64'), ct.toString('base64')].join('.');
}

function decryptSecret(value) {
  const parts = String(value || '').split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('unrecognised secret format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(parts[1], 'base64'));
  decipher.setAuthTag(Buffer.from(parts[2], 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64')), decipher.final()]).toString('utf8');
}

// ---------------------------------------------------------------------------
// Telegram Bot API client
// ---------------------------------------------------------------------------
// BotFather tokens look like "123456789:AAH..." - digits, a colon, then the
// secret. Anything else is rejected before it can reach a URL.
const TOKEN_RE = /^\d{5,15}:[A-Za-z0-9_-]{25,128}$/;

function normaliseToken(value) {
  const token = String(value || '').trim();
  if (!TOKEN_RE.test(token)) {
    throw Object.assign(new Error('That does not look like a bot token. It should look like 123456789:AA...'), {
      statusCode: 400,
      code: 'bad_token',
    });
  }
  return token;
}

function normaliseChatId(value) {
  const chatId = String(value == null ? '' : value).trim();
  // Groups and channels use negative ids ("-1001234567890"); private chats are
  // positive. A @channelusername is also valid.
  if (!/^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{3,64})$/.test(chatId)) {
    throw Object.assign(new Error('Chat ID must be a number (e.g. 123456789 or -1001234567890).'), {
      statusCode: 400,
      code: 'bad_chat_id',
    });
  }
  return chatId;
}

async function callApi(token, method, payload) {
  const url = API_BASE + '/bot' + token + '/' + method;
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch (err) {
    const e = new Error(
      err && err.name === 'TimeoutError'
        ? 'Telegram did not answer in time. Check the server\'s outbound connection.'
        : 'Could not reach Telegram: ' + (err && err.message ? err.message : 'network error')
    );
    e.code = 'telegram_unreachable';
    e.statusCode = 502;
    throw e;
  }

  let body = null;
  try {
    body = await res.json();
  } catch (err) {
    body = null;
  }

  if (!res.ok || !body || body.ok !== true) {
    const description = (body && body.description) || 'HTTP ' + res.status;
    let message = description;
    let code = 'telegram_error';
    if (res.status === 401) {
      message = 'Telegram rejected the bot token. Copy it again from @BotFather.';
      code = 'bad_token';
    } else if (res.status === 403) {
      message =
        'The bot is not allowed to message that chat. Open the bot in Telegram, press Start (or add it to the group) and try again.';
      code = 'chat_forbidden';
    } else if (res.status === 400 && /chat not found/i.test(description)) {
      message = 'Chat not found. Send /start to your bot first, then use "Detect chat ID".';
      code = 'chat_not_found';
    } else if (res.status === 429) {
      const retry = body && body.parameters && body.parameters.retry_after;
      message = 'Telegram is rate limiting this bot' + (retry ? ' (retry in ' + retry + 's)' : '') + '.';
      code = 'rate_limited';
    }
    const e = new Error(message);
    e.code = code;
    e.statusCode = res.status === 401 || res.status === 400 ? 400 : 502;
    e.telegramStatus = res.status;
    throw e;
  }

  return body.result;
}

async function getMe(token) {
  return callApi(normaliseToken(token), 'getMe', {});
}

/**
 * Find the chat the user has already started a conversation with.
 * Telegram only reveals a chat id after the user contacts the bot, so this is
 * the reliable way to fill the field without asking them to dig through
 * getUpdates themselves.
 */
async function detectChat(token) {
  const t = normaliseToken(token);
  const updates = await callApi(t, 'getUpdates', {
    limit: 100,
    timeout: 0,
    allowed_updates: ['message', 'channel_post', 'my_chat_member'],
  });

  const chats = [];
  for (const update of Array.isArray(updates) ? updates : []) {
    const message = update.message || update.channel_post || null;
    const member = update.my_chat_member || null;
    const chat = (message && message.chat) || (member && member.chat) || null;
    if (chat && chat.id != null) {
      chats.push({
        id: String(chat.id),
        label: chat.title || [chat.first_name, chat.last_name].filter(Boolean).join(' ') || chat.username || String(chat.id),
        type: chat.type || null,
      });
    }
  }

  if (!chats.length) {
    const e = new Error(
      'No chat found. Open Telegram, start a chat with your bot and press Start (or send any message), then try again.'
    );
    e.code = 'no_chat';
    e.statusCode = 400;
    throw e;
  }
  // Most recent update wins.
  const chat = chats[chats.length - 1];
  return { chat_id: chat.id, label: chat.label, type: chat.type };
}

/**
 * Convenience wrapper: detect the chat with the supplied token, or with the
 * token already stored for this user when the field is left blank.
 */
async function detectChatForUser(userId, providedToken) {
  let token = providedToken && String(providedToken).trim() ? normaliseToken(providedToken) : null;
  if (!token) {
    const row = stmts.getConfig.get(userId);
    if (!row) {
      throw Object.assign(new Error('Enter your bot token first, then press Detect chat.'), {
        statusCode: 400,
        code: 'token_required',
      });
    }
    token = decryptSecret(row.token_enc);
  }
  return detectChat(token);
}

async function sendMessage(token, chatId, text) {
  return callApi(normaliseToken(token), 'sendMessage', {
    chat_id: normaliseChatId(chatId),
    text: String(text || '').slice(0, 4000),
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  });
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function utcStamp(date) {
  return (date || new Date()).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function deviceMessage(kind, device) {
  const verb = kind === 'connected' ? 'Device connected' : 'Device disconnected';
  return [
    '<b>' + verb + '</b>',
    '<b>' + escapeHtml(device.name || 'Unnamed device') + '</b>',
    'Group: ' + escapeHtml(device.group_name || 'unknown'),
    'Time: ' + utcStamp(),
  ].join('\n');
}

function adminDeviceMessage(events) {
  if (events.length === 1) {
    const e = events[0];
    return [
      '<b>[Admin] Device ' + (e.kind === 'connected' ? 'connected' : 'disconnected') + '</b>',
      'User: ' + escapeHtml(e.email),
      'Device: ' + escapeHtml(e.device.name || 'Unnamed device'),
      'Group: ' + escapeHtml(e.device.group_name || 'unknown'),
      'Time: ' + utcStamp(),
    ].join('\n');
  }
  const lines = events.slice(0, MAX_EVENTS_PER_ADMIN_MESSAGE).map((e) => {
    const word = e.kind === 'connected' ? 'ONLINE ' : 'OFFLINE';
    return word + '  ' + escapeHtml(e.device.name || 'Unnamed device') +
      '  (' + escapeHtml(e.device.group_name || 'unknown') + ')  - ' + escapeHtml(e.email);
  });
  const extra = events.length > MAX_EVENTS_PER_ADMIN_MESSAGE
    ? '\n...and ' + (events.length - MAX_EVENTS_PER_ADMIN_MESSAGE) + ' more'
    : '';
  return '<b>[Admin] ' + events.length + ' device events</b>\n' + lines.join('\n') + extra +
    '\nTime: ' + utcStamp();
}

// ---------------------------------------------------------------------------
// Per-user configuration
// ---------------------------------------------------------------------------
const stmts = {
  getConfig: db.prepare('SELECT * FROM portal_telegram WHERE user_id = ?'),
  listEnabled: db.prepare(
    `SELECT t.*, u.email, u.mc_userid, u.status FROM portal_telegram t
       JOIN portal_users u ON u.id = t.user_id
      WHERE t.enabled = 1`
  ),
  insertConfig: db.prepare(
    `INSERT INTO portal_telegram
       (user_id, token_enc, chat_id, chat_label, enabled, notify_connect, notify_disconnect, verified_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ),
  updateConfig: db.prepare(
    `UPDATE portal_telegram SET token_enc = ?, chat_id = ?, chat_label = ?, enabled = ?,
            notify_connect = ?, notify_disconnect = ?, verified_at = ?, last_error = NULL, updated_at = ?
      WHERE user_id = ?`
  ),
  setEnabled: db.prepare('UPDATE portal_telegram SET enabled = ?, updated_at = ? WHERE user_id = ?'),
  setResult: db.prepare('UPDATE portal_telegram SET last_error = ?, last_sent_at = ?, updated_at = ? WHERE user_id = ?'),
  deleteConfig: db.prepare('DELETE FROM portal_telegram WHERE user_id = ?'),

  listStates: db.prepare('SELECT * FROM portal_device_state WHERE user_id = ?'),
  upsertState: db.prepare(
    `INSERT INTO portal_device_state (user_id, device_id, name, group_name, online, changed_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, device_id) DO UPDATE SET
       name = excluded.name, group_name = excluded.group_name, online = excluded.online,
       changed_at = excluded.changed_at, updated_at = excluded.updated_at`
  ),
  deleteState: db.prepare('DELETE FROM portal_device_state WHERE user_id = ? AND device_id = ?'),

  getSetting: db.prepare('SELECT value FROM portal_settings WHERE key = ?'),
  putSetting: db.prepare(
    `INSERT INTO portal_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  ),
  deleteSetting: db.prepare('DELETE FROM portal_settings WHERE key = ?'),
};

/**
 * What the browser is allowed to see. Never includes the token.
 */
function publicSettings(userId) {
  const row = stmts.getConfig.get(userId);
  if (!row) return { configured: false, enabled: false, notify_connect: true, notify_disconnect: true };
  let hint = null;
  try {
    const token = decryptSecret(row.token_enc);
    hint = token.slice(-4);
  } catch (err) {
    hint = null;
  }
  return {
    configured: true,
    enabled: !!row.enabled,
    chat_id: row.chat_id,
    chat_label: row.chat_label || null,
    token_hint: hint ? '...' + hint : null,
    notify_connect: !!row.notify_connect,
    notify_disconnect: !!row.notify_disconnect,
    verified_at: row.verified_at,
    last_sent_at: row.last_sent_at,
    last_error: row.last_error,
    updated_at: row.updated_at,
  };
}

/**
 * Create or update a user's configuration.
 * `bot_token` may be omitted on a later save; the stored token is then reused.
 */
async function saveSettings(userId, input) {
  const body = input || {};
  const existing = stmts.getConfig.get(userId);
  const now = new Date().toISOString();

  let tokenEnc;
  let verifiedAt = existing ? existing.verified_at : null;
  let chatLabel = existing ? existing.chat_label : null;

  if (body.bot_token != null && String(body.bot_token).trim() !== '') {
    const token = normaliseToken(body.bot_token);
    const me = await getMe(token); // throws on a bad token before anything is stored
    tokenEnc = encryptSecret(token);
    verifiedAt = now;
    if (me && me.username) chatLabel = '@' + me.username;
  } else if (existing) {
    tokenEnc = existing.token_enc;
  } else {
    throw Object.assign(new Error('A bot token is required the first time you enable Telegram.'), {
      statusCode: 400,
      code: 'token_required',
    });
  }

  const chatId = normaliseChatId(body.chat_id != null ? body.chat_id : existing ? existing.chat_id : '');
  const enabled = body.enabled == null ? (existing ? !!existing.enabled : true) : !!body.enabled;
  const notifyConnect = body.notify_connect == null ? (existing ? !!existing.notify_connect : true) : !!body.notify_connect;
  const notifyDisconnect =
    body.notify_disconnect == null ? (existing ? !!existing.notify_disconnect : true) : !!body.notify_disconnect;

  if (existing) {
    stmts.updateConfig.run(
      tokenEnc,
      chatId,
      chatLabel,
      enabled ? 1 : 0,
      notifyConnect ? 1 : 0,
      notifyDisconnect ? 1 : 0,
      verifiedAt,
      now,
      userId
    );
  } else {
    stmts.insertConfig.run(
      userId,
      tokenEnc,
      chatId,
      chatLabel,
      enabled ? 1 : 0,
      notifyConnect ? 1 : 0,
      notifyDisconnect ? 1 : 0,
      verifiedAt,
      now,
      now
    );
  }

  return publicSettings(userId);
}

function deleteSettings(userId) {
  stmts.deleteConfig.run(userId);
  db.prepare('DELETE FROM portal_device_state WHERE user_id = ?').run(userId);
  return { configured: false, enabled: false, notify_connect: true, notify_disconnect: true };
}

function setEnabled(userId, enabled) {
  const row = stmts.getConfig.get(userId);
  if (!row) {
    throw Object.assign(new Error('Telegram is not configured for this account.'), {
      statusCode: 404,
      code: 'not_configured',
    });
  }
  stmts.setEnabled.run(enabled ? 1 : 0, new Date().toISOString(), userId);
  return publicSettings(userId);
}

async function sendTest(userId) {
  const row = stmts.getConfig.get(userId);
  if (!row) {
    throw Object.assign(new Error('Configure Telegram before sending a test message.'), {
      statusCode: 400,
      code: 'not_configured',
    });
  }
  const token = decryptSecret(row.token_enc);
  try {
    await sendMessage(
      token,
      row.chat_id,
      '<b>EXagent</b>\nTest notification from your dashboard. ' +
        'Device connect/disconnect alerts will arrive in this chat.'
    );
    stmts.setResult.run(null, new Date().toISOString(), new Date().toISOString(), userId);
    return { sent: true };
  } catch (err) {
    stmts.setResult.run(err.message, null, new Date().toISOString(), userId);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Administrator configuration (stored in portal_settings)
// ---------------------------------------------------------------------------
const ADMIN_KEY = 'admin_telegram';

function readAdminRow() {
  const row = stmts.getSetting.get(ADMIN_KEY);
  if (!row || !row.value) return null;
  try {
    return JSON.parse(row.value);
  } catch (err) {
    return null;
  }
}

function getAdminConfig() {
  const stored = readAdminRow();
  if (!stored) {
    // Fall back to environment configuration, so a deployment can wire the
    // admin feed without touching the UI.
    const token = process.env.ADMIN_TELEGRAM_BOT_TOKEN;
    const chatId = process.env.ADMIN_TELEGRAM_CHAT_ID;
    if (!token || !chatId) return { configured: false, enabled: false };
    return {
      configured: true,
      enabled: true,
      chat_id: chatId,
      chat_label: null,
      token_hint: String(token).slice(-4) ? '...' + String(token).slice(-4) : null,
      notify_connect: true,
      notify_disconnect: true,
      notify_signups: true,
      notify_logins: true,
      source: 'env',
    };
  }
  let hint = null;
  try {
    hint = decryptSecret(stored.token_enc).slice(-4);
  } catch (err) {
    hint = null;
  }
  return {
    configured: !!stored.token_enc,
    enabled: !!stored.enabled,
    chat_id: stored.chat_id || null,
    chat_label: stored.chat_label || null,
    token_hint: hint ? '...' + hint : null,
    notify_connect: stored.notify_connect !== false,
    notify_disconnect: stored.notify_disconnect !== false,
    notify_signups: stored.notify_signups !== false,
    notify_logins: stored.notify_logins !== false,
    updated_at: stored.updated_at || null,
    source: 'db',
  };
}

function adminToken() {
  const stored = readAdminRow();
  if (stored && stored.token_enc) return decryptSecret(stored.token_enc);
  return process.env.ADMIN_TELEGRAM_BOT_TOKEN || null;
}

async function saveAdminConfig(input) {
  const body = input || {};
  const stored = readAdminRow() || {};
  const now = new Date().toISOString();

  let tokenEnc = stored.token_enc || null;
  let chatLabel = stored.chat_label || null;
  if (body.bot_token != null && String(body.bot_token).trim() !== '') {
    const token = normaliseToken(body.bot_token);
    const me = await getMe(token);
    tokenEnc = encryptSecret(token);
    if (me && me.username) chatLabel = '@' + me.username;
  }
  const chatId = body.chat_id != null ? normaliseChatId(body.chat_id) : stored.chat_id || null;
  if (!tokenEnc) {
    throw Object.assign(new Error('A bot token is required the first time you enable admin notifications.'), {
      statusCode: 400,
      code: 'token_required',
    });
  }
  if (!chatId) {
    throw Object.assign(new Error('A chat ID is required for admin notifications.'), {
      statusCode: 400,
      code: 'chat_required',
    });
  }

  const record = {
    token_enc: tokenEnc,
    chat_id: chatId,
    chat_label: chatLabel,
    enabled: body.enabled == null ? stored.enabled !== false : !!body.enabled,
    notify_connect: body.notify_connect == null ? stored.notify_connect !== false : !!body.notify_connect,
    notify_disconnect: body.notify_disconnect == null ? stored.notify_disconnect !== false : !!body.notify_disconnect,
    notify_signups: body.notify_signups == null ? stored.notify_signups !== false : !!body.notify_signups,
    notify_logins: body.notify_logins == null ? stored.notify_logins !== false : !!body.notify_logins,
    updated_at: now,
  };
  stmts.putSetting.run(ADMIN_KEY, JSON.stringify(record), now);
  return getAdminConfig();
}

function deleteAdminConfig() {
  stmts.deleteSetting.run(ADMIN_KEY);
  return { configured: false, enabled: false };
}

async function sendAdminTest() {
  const cfg = getAdminConfig();
  const token = adminToken();
  if (!cfg.configured || !token || !cfg.chat_id) {
    throw Object.assign(new Error('Admin Telegram is not configured.'), {
      statusCode: 400,
      code: 'not_configured',
    });
  }
  await sendMessage(
    token,
    cfg.chat_id,
    '<b>EXagent - admin</b>\nTest notification. You will receive device and account events here.'
  );
  return { sent: true };
}

/**
 * Fire-and-forget account event for the admin feed. Never throws.
 * kind: 'signup' | 'access_granted' | 'login'
 */
async function notifyAdminUserEvent(kind, info) {
  try {
    const cfg = getAdminConfig();
    if (!cfg.configured || !cfg.enabled) return { skipped: true };
    if ((kind === 'signup' || kind === 'access_granted') && !cfg.notify_signups) return { skipped: true };
    if (kind === 'login' && !cfg.notify_logins) return { skipped: true };
    const token = adminToken();
    if (!token) return { skipped: true };

    const label =
      kind === 'login' ? 'User signed in' : kind === 'access_granted' ? 'New account (access granted)' : 'New account created';
    const lines = [
      '<b>[Admin] ' + label + '</b>',
      'Email: ' + escapeHtml(info.email),
      info.name ? 'Name: ' + escapeHtml(info.name) : null,
      info.ip ? 'IP: ' + escapeHtml(info.ip) : null,
      'Time: ' + utcStamp(),
    ].filter(Boolean);
    await sendMessage(token, cfg.chat_id, lines.join('\n'));
    return { sent: true };
  } catch (err) {
    console.warn('[telegram] admin ' + kind + ' notification failed: ' + err.message);
    return { sent: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// Presence watcher
// ---------------------------------------------------------------------------
let timer = null;
let running = false;

function applyTransitions(userId, devices) {
  const previous = new Map(stmts.listStates.all(userId).map((r) => [r.device_id, r]));
  const baseline = previous.size === 0;
  const now = new Date().toISOString();
  const events = [];
  const seen = new Set();

  for (const device of devices) {
    const id = device.id;
    if (!id) continue;
    seen.add(id);
    const prev = previous.get(id);
    const online = !!device.online;

    if (!prev) {
      // First observation of a device: a device that is already online is only
      // announced when this is NOT the user's initial baseline, otherwise
      // enabling notifications would replay every device at once.
      if (online && !baseline) events.push({ kind: 'connected', device });
      stmts.upsertState.run(userId, id, device.name || null, device.group_name || null, online ? 1 : 0, now, now);
      continue;
    }

    if (!!prev.online !== online) {
      events.push({ kind: online ? 'connected' : 'disconnected', device });
      stmts.upsertState.run(userId, id, device.name || null, device.group_name || null, online ? 1 : 0, now, now);
    } else if (prev.name !== (device.name || null) || prev.group_name !== (device.group_name || null)) {
      stmts.upsertState.run(
        userId,
        id,
        device.name || null,
        device.group_name || null,
        online ? 1 : 0,
        prev.changed_at,
        now
      );
    }
  }

  // Forget devices that were removed from the account entirely.
  for (const id of previous.keys()) {
    if (!seen.has(id)) stmts.deleteState.run(userId, id);
  }

  return events;
}

/**
 * Poll once. Safe to call on demand (tests / admin endpoint); a second
 * concurrent call is skipped.
 */
async function pollOnce() {
  if (running) return { skipped: 'busy' };
  running = true;
  try {
    const adminCfg = getAdminConfig();
    const adminDeviceFeed = !!(adminCfg.configured && adminCfg.enabled &&
      (adminCfg.notify_connect || adminCfg.notify_disconnect));

    // Users with their own notifications enabled are always polled.
    const targets = new Map();
    for (const row of stmts.listEnabled.all()) {
      targets.set(row.user_id, { row, config: row, email: row.email });
    }

    // The admin feed needs every active account, configured or not.
    if (adminDeviceFeed) {
      const all = db
        .prepare("SELECT * FROM portal_users WHERE mc_userid IS NOT NULL AND status IN ('trial','extended')")
        .all();
      for (const user of all) {
        if (!targets.has(user.id)) targets.set(user.id, { row: null, config: null, email: user.email });
      }
    }

    const summary = { polled: 0, sent: 0, errors: 0, events: 0 };
    if (!targets.size) return summary;

    const adminEvents = [];

    for (const target of targets.values()) {
      const userId = target.config ? target.config.user_id : null;
      const email = target.email;

      // Resolve the MeshCentral account id for this user.
      let mcUserid = target.config ? target.config.mc_userid : null;
      if (!mcUserid && userId) {
        const row = db.prepare('SELECT mc_userid FROM portal_users WHERE id = ?').get(userId);
        mcUserid = row ? row.mc_userid : null;
      }
      if (!mcUserid) continue;

      let devices;
      try {
        devices = await provision.listDevicesForUser(mcUserid);
      } catch (err) {
        summary.errors += 1;
        console.warn('[telegram] device poll failed for ' + email + ': ' + err.message);
        continue;
      }
      summary.polled += 1;

      const events = applyTransitions(userId || -1, devices);
      summary.events += events.length;

      if (!events.length) continue;

      // per-user delivery
      if (target.config && target.config.enabled) {
        const token = (() => {
          try {
            return decryptSecret(target.config.token_enc);
          } catch (err) {
            return null;
          }
        })();
        if (token) {
          for (const event of events) {
            const wanted = event.kind === 'connected' ? target.config.notify_connect : target.config.notify_disconnect;
            if (!wanted) continue;
            try {
              await sendMessage(token, target.config.chat_id, deviceMessage(event.kind, event.device));
              summary.sent += 1;
              stmts.setResult.run(null, new Date().toISOString(), new Date().toISOString(), userId);
            } catch (err) {
              summary.errors += 1;
              stmts.setResult.run(err.message, null, new Date().toISOString(), userId);
              console.warn('[telegram] send failed for ' + email + ': ' + err.message);
            }
          }
        }
      }

      // admin aggregation
      if (adminDeviceFeed) {
        for (const event of events) {
          const wanted = event.kind === 'connected' ? adminCfg.notify_connect : adminCfg.notify_disconnect;
          if (wanted) adminEvents.push({ kind: event.kind, device: event.device, email });
        }
      }
    }

    if (adminEvents.length) {
      const token = adminToken();
      if (token) {
        try {
          await sendMessage(token, adminCfg.chat_id, adminDeviceMessage(adminEvents));
          summary.sent += 1;
        } catch (err) {
          summary.errors += 1;
          console.warn('[telegram] admin device feed failed: ' + err.message);
        }
      }
    }

    return summary;
  } finally {
    running = false;
  }
}

function startWatcher() {
  if (timer) return timer;
  timer = setInterval(() => {
    pollOnce().catch((err) => console.warn('[telegram] poll failed: ' + err.message));
  }, POLL_SECONDS * 1000);
  timer.unref();

  // Warm the presence baseline shortly after boot so the first user-visible
  // event is a real transition, not a replay of every device.
  const warm = setTimeout(() => {
    pollOnce().catch((err) => console.warn('[telegram] initial poll failed: ' + err.message));
  }, 15000);
  warm.unref();

  console.log('[telegram] watcher started (every ' + POLL_SECONDS + 's)');
  return timer;
}

module.exports = {
  // user settings
  publicSettings,
  saveSettings,
  deleteSettings,
  setEnabled,
  sendTest,
  detectChat,
  detectChatForUser,
  // admin settings
  getAdminConfig,
  saveAdminConfig,
  deleteAdminConfig,
  sendAdminTest,
  notifyAdminUserEvent,
  // watcher
  pollOnce,
  startWatcher,
  // exposed for tests
  _internal: { encryptSecret, decryptSecret, normaliseToken, normaliseChatId, deviceMessage, applyTransitions, stmts },
  POLL_SECONDS,
};
