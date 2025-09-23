#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/00_env.sh"
need openssl

mkdirp "${ROOTCA_DIR}" "${CERTS_DIR}"

umask 077
if [[ ! -s "${CA_KEY}" ]]; then
  log "Generating RootCA key → ${CA_KEY}"
  openssl genrsa -out "${CA_KEY}" "${ROOT_BITS}"
else
  log "RootCA key exists → ${CA_KEY}"
fi

if [[ ! -s "${CA_CRT}" ]]; then
  log "Generating RootCA cert → ${CA_CRT}"
  openssl req -new -x509 -key "${CA_KEY}" -out "${CA_CRT}" \
    -days "${ROOT_DAYS}" -sha256 -config "${CONF_DIR}/root_ca.cnf" -set_serial 0
else
  log "RootCA cert exists → ${CA_CRT}"
fi

log "RootCA ready."

