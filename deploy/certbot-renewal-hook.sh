#!/bin/bash
# Keep MeshCentral's webserver certificate in sync with the Let's Encrypt
# certificate used on the public edge. MeshCentral reads the web certificate
# at startup and agents validate the TLS cert they see against it, so the copy
# must be refreshed (and MeshCentral restarted) whenever certbot renews.
set -e
cp -L /etc/letsencrypt/live/mysystemservices.exrmm.com/fullchain.pem /opt/meshcentral/meshcentral-data/webserver-cert-public.crt
cp -L /etc/letsencrypt/live/mysystemservices.exrmm.com/privkey.pem /opt/meshcentral/meshcentral-data/webserver-cert-private.key
chmod 600 /opt/meshcentral/meshcentral-data/webserver-cert-private.key
chown root:root /opt/meshcentral/meshcentral-data/webserver-cert-public.crt /opt/meshcentral/meshcentral-data/webserver-cert-private.key
systemctl restart meshcentral
