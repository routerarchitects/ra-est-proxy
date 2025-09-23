#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/00_env.sh"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <client_id> <dest_path>"
  echo "  remote: $0 dc6279652f19 root@200.20.20.107:/etc/ucentral"
  echo "  local : $0 dc6279652f19 /tmp/ucentral"
  exit 1
fi

CID="$1"; DEST="$2"
CLIENT_KEY="${CERTS_DIR}/client-${CID}.key"
CLIENT_CRT="${CERTS_DIR}/client-${CID}.crt"
CA_CRT="${ROOTCA_DIR}/ca_cert.pem"

for f in "${CLIENT_KEY}" "${CLIENT_CRT}" "${CA_CRT}"; do
  [[ -s "$f" ]] || { echo "Missing file: $f" >&2; exit 1; }
done

COPY=cp
if [[ "$DEST" == *"@"*":"* ]]; then
  COPY=scp
fi

log "Copying client(${CID}) certs → ${DEST}"
"$COPY" "${CLIENT_KEY}" "${DEST}/key.pem"
"$COPY" "${CLIENT_CRT}" "${DEST}/cert.pem"
"$COPY" "${CA_CRT}"     "${DEST}/insta.pem"
log "Done."
