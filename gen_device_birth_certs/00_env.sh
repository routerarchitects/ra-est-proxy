#!/usr/bin/env bash
set -euo pipefail

# Resolve to repo dir (independent of caller's PWD)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Base and subdirs
BASE_DIR="${SCRIPT_DIR}"
CONF_DIR="${BASE_DIR}/conf"
CERTS_DIR="${BASE_DIR}/certs"

# Structured layout
ROOTCA_DIR="${CERTS_DIR}/rootca"
SERVER_DIR="${CERTS_DIR}/server"
CLIENTS_DIR="${CERTS_DIR}/clients"

# Root CA files
CA_KEY="${ROOTCA_DIR}/ca_key.pem"
CA_CRT="${ROOTCA_DIR}/ca_cert.pem"

# Server files
SERVER_KEY="${SERVER_DIR}/server.key"
SERVER_CRT="${SERVER_DIR}/server.crt"

# Client template (each client gets client-<id>.key/crt)
CLIENT_KEY_TMPL="${CLIENTS_DIR}/client-<id>.key"
CLIENT_CRT_TMPL="${CLIENTS_DIR}/client-<id>.crt"

# Defaults
ROOT_BITS="${ROOT_BITS:-4096}"
LEAF_BITS="${LEAF_BITS:-2048}"
ROOT_DAYS="${ROOT_DAYS:-365}"
LEAF_DAYS="${LEAF_DAYS:-365}"

# Helpers
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
mkdirp(){ mkdir -p "$@"; }
log(){ printf "\033[1;36m[INFO]\033[0m %s\n" "$*"; }

