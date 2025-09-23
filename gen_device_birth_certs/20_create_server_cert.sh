#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/00_env.sh"
need openssl

# Ensure CA exists
"$(dirname "$0")/10_create_root_ca.sh"

# Make sure the target dir exists
mkdir -p "${SERVER_DIR}"

# Use SERVER_* paths from env
SERVER_KEY="${SERVER_KEY:-"${SERVER_DIR}/server.key"}"
SERVER_CRT="${SERVER_CRT:-"${SERVER_DIR}/server.crt"}"

umask 077
log "Generating server key → ${SERVER_KEY}"
openssl genrsa -out "${SERVER_KEY}" "${LEAF_BITS}"

log "Creating & signing server cert (no CSR file saved)"
openssl req -new -key "${SERVER_KEY}" -config "${CONF_DIR}/server.cnf" \
| openssl x509 -req -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${SERVER_CRT}" -days "${LEAF_DAYS}" -sha256 \
    -extfile "${CONF_DIR}/server.cnf" -extensions v3_req

log "Server cert:"
openssl x509 -in "${SERVER_CRT}" -noout -subject -issuer -dates

