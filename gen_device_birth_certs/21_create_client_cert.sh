#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/00_env.sh"
need openssl

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <client_id>   # e.g. dc6279652f19"; exit 1;
fi
CLIENT_ID="$1"

# Optional: enforce 12-hex MAC-like ID (remove if not desired)
if ! [[ "${CLIENT_ID}" =~ ^[A-Fa-f0-9]{12}$ ]]; then
  echo "Error: <client_id> must be 12 hex chars (e.g. dc6279652f19)"; exit 1;
fi

# Ensure CA exists
"$(dirname "$0")/10_create_root_ca.sh"

mkdirp "${CERTS_DIR}"
CLIENT_KEY="${CERTS_DIR}/client-${CLIENT_ID}.key"
CLIENT_CRT="${CERTS_DIR}/client-${CLIENT_ID}.crt"

umask 077
log "Generating client key → ${CLIENT_KEY}"
openssl genrsa -out "${CLIENT_KEY}" "${LEAF_BITS}"

log "Creating & signing client cert for CN=${CLIENT_ID} (no CSR file saved)"
openssl req -new -key "${CLIENT_KEY}" -config "${CONF_DIR}/client.cnf" -subj "/CN=${CLIENT_ID}" \
| openssl x509 -req -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${CLIENT_CRT}" -days "${LEAF_DAYS}" -sha256 \
    -extfile "${CONF_DIR}/client.cnf" -extensions v3_req

log "Client cert:"
openssl x509 -in "${CLIENT_CRT}" -noout -subject -issuer -dates

