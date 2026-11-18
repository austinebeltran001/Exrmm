# Exrmm — EXagent RMM Portal

Source code for the EXagent remote-monitoring-and-management portal: a
multi-tenant web console that provisions MeshCentral device groups per client,
builds branded silent agents and MSI installers, and manages devices, alerts,
accounts, trials and Telegram notifications.

Copyright (C) 2026 EX 313 LTD. Licensed under the **GNU Affero General Public
License v3.0** (`AGPL-3.0-only`) — see [LICENSE](LICENSE).

Everything runs on a single server:

| Component          | Where                                     |
|--------------------|-------------------------------------------|
| Portal (this repo) | `/opt/exrmm/portal`, systemd `exrmm-portal`, `127.0.0.1:8090` |
| MeshCentral        | `/opt/meshcentral`, systemd `meshcentral`, `127.0.0.1:8446` (loopback only) |
| Public edge        | nginx `443` (portal + agent downloads) and `8443` (MeshCentral console + agent channel) |

## Repository layout

```
backend/            Node.js API server + MeshCentral client
  src/              server, auth, provisioning, installer/MSI builders, mail, telegram, db
  package.json      dependencies (better-sqlite3, dotenv, express, nodemailer, ws)
frontend/dist/      prebuilt dashboard (served as static files)
scripts/            installer pipeline sources (NSIS templates, WiX template,
                    build_msi.py) and operational probe/selftest scripts
deploy/             nginx site configs, systemd units, certbot renewal hook,
                    MeshCentral config reference
.env.example        every environment variable the backend reads (placeholders)
```

## Quick start

```bash
cp .env.example .env          # fill in real values
cd backend && npm install     # node >= 22
npm start                     # listens on BIND_HOST:PORT (default 127.0.0.1:8090)
```

Install MeshCentral separately (`npm install meshcentral`) and point
`MESH_URL` at its HTTPS listener; keep MeshCentral bound to loopback and
publish it through nginx (see `deploy/`).

## Agent installers

`scripts/` contains the full installer pipeline:

- `silent-wrapper-template.nsi` — single-click silent Windows agent wrapper
- `installer-template.nsi`, `msi-template.wxs`, `msi-runner.nsi` — MSI path
- `build_msi.py` — MSI builder (group name drives product/service names)
- `rebuild_msi_ht.js` — portal-side rebuild entry point

Agents are downloaded from MeshCentral, stamped with the group's mesh id and
the public server URL, then wrapped/built per client. Installers are written to
`INSTALLERS_DIR` at runtime (not stored in this repository).

## Deployment

`deploy/` mirrors the live server configuration:

- `nginx/mysystemservices.exrmm.com.conf` — portal edge (443), including the
  `/meshagents` route that serves one-click silent installers
- `nginx/zz-meshcentral-8443.conf` — MeshCentral console/agent listener (8443)
- `systemd/` — `exrmm-portal.service`, `meshcentral.service`
- `certbot-renewal-hook.sh` — keeps MeshCentral's webserver certificate in
  sync with the Let's Encrypt certificate on renewal (MeshCentral reads its
  certificate at startup, and agents validate the TLS cert they see against
  it, so the copy must be refreshed on every renewal)
- `meshcentral-config.json` — reference MeshCentral settings

## Note

A number of internal security modules (and their API routes, UI assets and
agent payloads) are intentionally excluded from this public copy. The
`backend/src/server.js` in this repository is the sanitized version with those
routes removed; everything else is complete.

## Licence

Copyright (C) 2026 EX 313 LTD — <https://exrmm.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

The complete licence text is in [LICENSE](LICENSE).

EXagent and the EXagent logo are trademarks of EX 313 LTD.

