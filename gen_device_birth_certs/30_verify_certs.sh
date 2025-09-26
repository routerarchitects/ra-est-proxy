#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/00_env.sh"
need openssl

SERVER_KEY="${SERVER_KEY:-"${CERTS_DIR}/server.key"}"
SERVER_CRT="${SERVER_CRT:-"${CERTS_DIR}/server.crt"}"

log "Verify server cert against CA"
openssl verify -CAfile "${CA_CRT}" "${SERVER_CRT}" || true

if [[ $# -eq 1 ]]; then
  CID="$1"
  CLIENT_KEY="${CERTS_DIR}/client-${CID}.key"
  CLIENT_CRT="${CERTS_DIR}/client-${CID}.crt"
  log "Verify client(${CID}) cert against CA"
  openssl verify -CAfile "${CA_CRT}" "${CLIENT_CRT}" || true

  echo
  log "Client modulus match check"
  openssl x509 -noout -modulus -in "${CLIENT_CRT}" | openssl md5
  openssl rsa  -noout -modulus -in "${CLIENT_KEY}" | openssl md5
fi

echo
log "Server modulus match check"
openssl x509 -noout -modulus -in "${SERVER_CRT}" | openssl md5
openssl rsa  -noout -modulus -in "${SERVER_KEY}" | openssl md5

