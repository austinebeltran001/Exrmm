// Ex Softwares LLC portal - set MeshCentral's invalid-login filter.
//
// Runs INSIDE the MeshCentral container (node /tmp/mc_set_maxinvalidlogin_ht.js).
// MeshCentral's default filter is { time: 10, count: 10, blocking: 'iprange' },
// which keys the bad-login table on the first three octets of the client
// address. The portal authenticates every user from one address, so a handful
// of wrong passwords submitted through the portal locked out the whole
// integration (users AND the admin channel) for ten minutes.
//
// Keying on the username instead keeps per-account brute-force protection
// without any cross-account collateral, and the short cooloff bounds how long a
// deliberately targeted account can be held off.

'use strict';

const fs = require('fs');

const CONFIG = '/opt/meshcentral/meshcentral-data/config.json';
const SETTINGS = {
  time: 10,          // sliding window, minutes
  count: 10,         // bad logins per key inside the window
  coolofftime: 2,    // minutes of cooloff once the threshold is reached
  blocking: 'username',
};

const config = JSON.parse(fs.readFileSync(CONFIG, 'utf8'));
config.settings = config.settings || {};
config.settings.maxinvalidlogin = SETTINGS;
fs.writeFileSync(CONFIG, JSON.stringify(config, null, 4) + '\n');

const written = JSON.parse(fs.readFileSync(CONFIG, 'utf8'));
console.log('maxinvalidlogin now: ' + JSON.stringify(written.settings.maxinvalidlogin));
console.log('settings keys: ' + Object.keys(written.settings).join(', '));
