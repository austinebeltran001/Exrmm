// EX SOFTWARE LLC portal - transactional email.
//
// Delivery goes through the same mailbox that MeshCentral uses for its native
// account emails (noreply@exrmm.com), so a trial user only ever sees one
// sender identity. Mail failures never break the API call that triggered them:
// every public function resolves and reports {sent:boolean, error?:string}.

'use strict';

const nodemailer = require('nodemailer');

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_SECURE = String(process.env.SMTP_SECURE || 'true') !== 'false';
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const MAIL_FOOTER_ADDRESS = process.env.MAIL_FOOTER_ADDRESS || 'EX SOFTWARE LLC';
const SUPPORT_FALLBACK = process.env.SUPPORT_EMAIL || 'support@exrmm.com';
const PUBLIC_PORTAL_URL =
  (process.env.PUBLIC_BASE_URL || 'https://app.exrmm.com').replace(/\/+$/, '') + '/';

const ACCENT = '#2dd4bf';
const PAGE_BG = '#0b1b2b';
const CARD_BG = '#102436';
const TEXT = '#FFFFFF';
const MUTED = 'rgba(255,255,255,0.62)';

let transporter = null;
let transportError = null;

function getTransport() {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    transportError = 'SMTP is not configured (SMTP_HOST/SMTP_USER/SMTP_PASS)';
    return null;
  }
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE, // true for 465
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    pool: true,
    maxConnections: 2,
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 30000,
  });
  return transporter;
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout({ heading, paragraphs, buttonText, buttonUrl, note }) {
  const paras = paragraphs
    .map(
      (p) =>
        '<p style="margin:0 0 16px;font-size:16px;line-height:1.6;color:' +
        MUTED +
        '">' +
        p +
        '</p>'
    )
    .join('');
  const button =
    buttonText && buttonUrl
      ? '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:8px 0 24px"><tr><td style="border-radius:10px;background:' +
        ACCENT +
        '"><a href="' +
        escapeHtml(buttonUrl) +
        '" style="display:inline-block;padding:14px 28px;font-size:16px;font-weight:700;color:' +
        PAGE_BG +
        ';text-decoration:none;border-radius:10px">' +
        escapeHtml(buttonText) +
        '</a></td></tr></table>' +
        '<p style="margin:0 0 24px;font-size:13px;line-height:1.6;color:' +
        MUTED +
        '">If the button does not work, copy this address into your browser:<br><span style="color:' +
        ACCENT +
        ';word-break:break-all">' +
        escapeHtml(buttonUrl) +
        '</span></p>'
      : '';
  const noteHtml = note
    ? '<p style="margin:0;font-size:13px;line-height:1.6;color:' +
      MUTED +
      '">' +
      note +
      '</p>'
    : '';

  return (
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' +
    escapeHtml(heading) +
    '</title></head>' +
    '<body style="margin:0;padding:0;background:' +
    PAGE_BG +
    ';">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:' +
    PAGE_BG +
    ';padding:32px 16px"><tr><td align="center">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:' +
    CARD_BG +
    ';border:1px solid rgba(255,255,255,0.10);border-radius:14px;padding:32px;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif">' +
    '<tr><td>' +
    '<div style="font-size:13px;letter-spacing:2px;text-transform:uppercase;color:' +
    ACCENT +
    ';font-weight:700;margin-bottom:8px">EXagent</div>' +
    '<h1 style="margin:0 0 20px;font-size:24px;line-height:1.3;color:' +
    TEXT +
    ';font-weight:700">' +
    escapeHtml(heading) +
    '</h1>' +
    paras +
    button +
    noteHtml +
    '</td></tr></table>' +
    '<p style="max-width:560px;margin:16px auto 0;font-size:12px;line-height:1.6;color:' +
    MUTED +
    ';text-align:center">' +
    escapeHtml(MAIL_FOOTER_ADDRESS) +
    ' &middot; Remote monitoring and management<br>' +
    'This message was sent because an account action was requested for this email address.</p>' +
    '</td></tr></table></body></html>'
  );
}

async function send({ to, subject, heading, paragraphs, buttonText, buttonUrl, note }) {
  const transport = getTransport();
  if (!transport) {
    console.error('[mail] skipped "' + subject + '": ' + transportError);
    return { sent: false, error: transportError };
  }
  try {
    await transport.sendMail({
      from: SMTP_FROM,
      to,
      subject,
      text: [heading, '', ...paragraphs.map((p) => p.replace(/<[^>]+>/g, '')), '', buttonUrl || '', '', MAIL_FOOTER_ADDRESS]
        .filter((line) => line !== undefined && line !== null)
        .join('\n'),
      html: layout({ heading, paragraphs, buttonText, buttonUrl, note }),
    });
    console.log('[mail] sent "' + subject + '" to ' + to);
    return { sent: true };
  } catch (err) {
    console.error('[mail] failed "' + subject + '" to ' + to + ': ' + err.message);
    return { sent: false, error: err.message };
  }
}

function sendEmailConfirmation({ to, name, confirmUrl }) {
  return send({
    to,
    subject: 'Confirm your EXagent email address',
    heading: 'Confirm your email address',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'Thanks for starting a EXagent trial. Confirm this email address so we can send you account notices, password resets and trial reminders.',
    ],
    buttonText: 'Confirm email address',
    buttonUrl: confirmUrl,
    note: 'Your trial is already active — you can sign in and install agents right now.',
  });
}

function sendTrialStarted({ to, name, consoleUrl, portalUrl, trialEndsAt }) {
  const ends = new Date(trialEndsAt);
  return send({
    to,
    subject: 'Your EXagent trial is live for 24 hours',
    heading: 'Your 24-hour trial is live',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'Your EXagent workspace is ready. Sign in to create a device group, download the EXagent, and manage your machines from any browser.',
      'The trial ends on ' + escapeHtml(ends.toUTCString()) + ' (UTC). After that, sign-in is disabled and the trial workspace is deleted 24 hours later.',
    ],
    buttonText: 'Open the dashboard',
    buttonUrl: portalUrl,
    note: 'The full remote-control console is available at <span style="color:' + ACCENT + '">' + escapeHtml(consoleUrl) + '</span>.',
  });
}

function sendTrialEndingSoon({ to, name, hoursLeft, supportUrl }) {
  return send({
    to,
    subject: 'Your EXagent trial ends in less than ' + hoursLeft + ' hours',
    heading: 'Your trial ends soon',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'Your EXagent trial has less than ' + hoursLeft + ' hours remaining. Devices you have enrolled today stop being manageable when the trial ends, and the workspace is deleted 24 hours after that.',
      'If you need more time, contact us before the trial expires and we will extend your access.',
    ],
    buttonText: 'Request more time',
    buttonUrl: supportUrl,
    note: 'Nothing is deleted until 24 hours after the trial ends.',
  });
}

function sendTrialExpired({ to, name, supportUrl }) {
  return send({
    to,
    subject: 'Your EXagent trial has ended',
    heading: 'Your trial has ended',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'Your 24-hour EXagent trial has ended, so sign-in is now disabled. Any enrolled devices and device groups are removed 24 hours from now.',
      'Reply to this address if you would like continued access.',
    ],
    buttonText: 'Contact us for access',
    buttonUrl: supportUrl,
    note: 'Agents that are already installed stop reporting once the account is removed, but you can uninstall them at any time from Windows Apps.',
  });
}

function sendWorkspaceDeleted({ to, name, supportUrl }) {
  return send({
    to,
    subject: 'Your EXagent trial workspace has been deleted',
    heading: 'Trial workspace deleted',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'The EXagent trial workspace for this email address has been deleted, including its device groups and account access. No further notices will be sent.',
      'If you would like a new workspace, contact us and we will set one up.',
    ],
    buttonText: 'Contact us',
    buttonUrl: supportUrl,
    note: 'This is the final message for this trial.',
  });
}

/**
 * Access-request flow: the account was created by the portal and the
 * sign-in credentials (email + generated password) are delivered here.
 * Receiving this mail proves the mailbox owner made the request, so the
 * address is treated as confirmed without an extra click.
 */
function sendAccessGranted({ to, name, email, password, portalUrl, consoleUrl, trialEndsAt }) {
  const ends = new Date(trialEndsAt);
  return send({
    to,
    subject: 'Your EXagent account is ready',
    heading: 'Your account is ready',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'Access to your EXagent workspace has been approved. Here are your sign-in credentials:',
      '<span style="display:block;background:' + PAGE_BG + ';border:1px solid rgba(255,255,255,0.14);border-radius:10px;padding:14px 18px;font-size:16px;line-height:1.7;color:' + TEXT + '"><strong>Sign-in email:</strong> ' + escapeHtml(email) + '<br><strong>Password:</strong> <span style="font-family:monospace;font-size:17px;color:' + ACCENT + '">' + escapeHtml(password) + '</span></span>',
      'Your 24-hour free trial ends on ' + escapeHtml(ends.toUTCString()) + ' (UTC). When it ends, reply to this email or message us on Telegram and we will confirm your plan and keep the workspace running.',
      'For security, change this password after your first sign-in: open the dashboard, go to <strong>Account</strong> and choose a new password. The password works for both the dashboard and the remote-control console at ' + escapeHtml(consoleUrl) + '.',
    ],
    buttonText: 'Sign in to your dashboard',
    buttonUrl: portalUrl,
    note: 'If you did not request access, ignore this email — nothing else will be sent to this address.',
  });
}

function sendDemoRequested({ to, name }) {
  return send({
    to,
    subject: 'We received your EXagent demo request',
    heading: 'Demo request received',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'Thanks for your interest in EXagent. We will email you shortly to schedule your personal demo at a time that suits you.',
      'In the meantime you can start a full-featured 24-hour trial — no waiting, no credit card.',
    ],
    buttonText: 'Start the 24-hour trial instead',
    buttonUrl: PUBLIC_PORTAL_URL,
    note: 'Prefer to talk first? Just reply to this email.',
  });
}

function sendDemoNotify({ to, name, email, company, preferred, notes, requestedAt }) {
  const lines = [
    '<strong>Name:</strong> ' + escapeHtml(name),
    '<strong>Email:</strong> ' + escapeHtml(email),
    company ? '<strong>Company:</strong> ' + escapeHtml(company) : null,
    preferred ? '<strong>Preferred time:</strong> ' + escapeHtml(preferred) : null,
    notes ? '<strong>Notes:</strong> ' + escapeHtml(notes) : null,
    '<strong>Requested:</strong> ' + escapeHtml(new Date(requestedAt).toUTCString()) + ' (UTC)',
  ].filter(Boolean);
  return send({
    to,
    subject: 'New demo request: ' + name + (company ? ' (' + company + ')' : ''),
    heading: 'New demo request',
    paragraphs: [
      'A visitor requested a product demo from the EX SOFTWARE LLC site:',
      '<span style="display:block;background:' + PAGE_BG + ';border:1px solid rgba(255,255,255,0.14);border-radius:10px;padding:14px 18px;font-size:15px;line-height:1.8;color:' + TEXT + '">' + lines.join('<br>') + '</span>',
      'Reply to their email address to schedule the demo.',
    ],
    buttonText: null,
    buttonUrl: null,
    note: 'The request is also stored in the portal database (demo_requests).',
  });
}

function sendPasswordReset({ to, name, resetUrl, hours = 2 }) {
  return send({
    to,
    subject: 'Reset your EXagent password',
    heading: 'Reset your password',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'We received a request to reset the password for your EXagent account. Choose a new password with the button below. The link works once and expires in ' + hours + ' hour(s).',
      'This is the same password that signs you in to the remote console, so any device group you own stays available right after the change.',
    ],
    buttonText: 'Choose a new password',
    buttonUrl: resetUrl,
    note: 'If you did not ask for this, ignore this email — your current password keeps working unchanged.',
  });
}

function sendPasswordChanged({ to, name, supportUrl, forgot }) {
  return send({
    to,
    subject: 'Your EXagent password was changed',
    heading: 'Your password was changed',
    paragraphs: [
      'Hi ' + escapeHtml(name) + ',',
      'The password for your EXagent account was just changed. It now works for both the dashboard and the remote console.',
      forgot
        ? 'This change was made through the password reset link you requested.'
        : 'This change was made from the account settings page of your dashboard.',
    ],
    buttonText: 'Contact support',
    buttonUrl: supportUrl,
    note: 'If you did not make this change, contact ' + escapeHtml(SUPPORT_FALLBACK) + ' immediately so we can lock the account.',
  });
}

// role='old' warns the address that is losing access, role='new' welcomes the
// replacement address and confirms it is now the login identity.
function sendEmailChanged({ to, name, oldEmail, newEmail, supportUrl, role = 'new' }) {
  const isOld = role === 'old';
  return send({
    to,
    subject: isOld
      ? 'Your EXagent sign-in email was changed'
      : 'Your EXagent sign-in email is now active',
    heading: isOld ? 'Sign-in email changed' : 'New sign-in email confirmed',
    paragraphs: isOld
      ? [
          'Hi ' + escapeHtml(name) + ',',
          'The EXagent account for this address was moved to ' + escapeHtml(newEmail) + '. This mailbox no longer receives account notices and can no longer sign in.',
          'Your device groups, enrolled machines and console access moved with the account.',
        ]
      : [
          'Hi ' + escapeHtml(name) + ',',
          'Your EXagent sign-in email is now ' + escapeHtml(newEmail) + ' (it was ' + escapeHtml(oldEmail) + ').',
          'Use this address with your existing password for both the dashboard and the remote console. Nothing else about the account changed.',
        ],
    buttonText: isOld ? 'Contact support' : 'Sign in',
    buttonUrl: isOld ? supportUrl : supportUrl,
    note: isOld
      ? 'If you did not request this change, contact ' + escapeHtml(SUPPORT_FALLBACK) + ' immediately.'
      : 'Future account notices, including trial reminders, go to this address.',
  });
}

async function verifyTransport() {
  const transport = getTransport();
  if (!transport) return { ok: false, error: transportError };
  try {
    await transport.verify();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = {
  verifyTransport,
  sendEmailConfirmation,
  sendAccessGranted,
  sendDemoRequested,
  sendDemoNotify,
  sendPasswordReset,
  sendPasswordChanged,
  sendEmailChanged,
  sendTrialStarted,
  sendTrialEndingSoon,
  sendTrialExpired,
  sendWorkspaceDeleted,
};
