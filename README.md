# ra-est-proxy

A Dockerized EST (Enrollment over Secure Transport) proxy for issuing device operational certificates.
Derivative of [grindsa/est_proxy](https://github.com/grindsa/est_proxy) (GPLv3). This fork is distributed under the **GNU AGPLv3**.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Clone](#clone)
- [Local Development (Quick Start)](#local-development-quick-start)
- [Generate EST Server and device birth Certificates](#generate-est-server-and-device-birth-certificates)
- [Configuration](#configuration)
- [Run (Docker Compose)](#run-docker-compose)
- [Verify](#verify)
- [Deploy on a cloud](#deploy-on-a-cloud-host)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview
`ra-est-proxy` exposes an HTTPS EST service to:
- return the CA/issuer chain (`cacerts`)
- enroll (`simpleenroll`) and re-enroll (`simplereenroll`) device certificates

You will:
1) Build/run the proxy via Docker, and
2) Prepare **server** cert/key and **issuer/CA** materials for signing device certificates.

---

## Prerequisites
- Docker Engine and Docker Compose (v2): `docker --version`, `docker compose version`
- OpenSSL (for certificate generation)
- (Optional) Your own Docker Hub repo if you plan to push a custom image

---

## Clone
```bash
git clone https://github.com/routerarchitects/ra-est-proxy.git
cd ra-est-proxy
```

---

# Local Development (Quick Start)

### Generate EST Server and device birth Certificates
When an AP device comes up, its est_client enrolls with the est_server (est_proxy) using its birth certificate to obtain an operational certificate. The device then uses this operational certificate to connect securely to its controller.

The gen_device_birth_certs script helps generate both the device birth certificates and the EST proxy (server) certificates.
For the est_proxy (server), it expects the following files:

```
examples/Docker/data/certs/
├── est-srv.crt.pem
└── est-srv.key.pem
```
 **If these files are missing (or during the first run), create them using the gen_device_birth_certs module — or use your own birth and server certificates and skip the certificate generation steps.**

1. Follow `gen_device_birth_certs/README.md` to generate a **est client and server certificate** and key.
2. Then copy them to the expected paths:
```bash
mkdir -p examples/Docker/data/certs/

cp gen_device_birth_certs/certs/server/server.crt    examples/Docker/data/certs/est-srv.crt.pem

cp gen_device_birth_certs/certs/server/server.key    examples/Docker/data/certs/est-srv.key.pem
```

### Copy the Issuer and Root CA certificate files needed for generating device operational certificates:
#### Note: If the certificates are generated using only the Root CA (without an Issuer), do not include any Issuer-related files or references in the est_proxy.cfg file.

Place them under:
```bash
mkdir -p ./examples/Docker/data/openssl-ca
mkdir -p ./examples/Docker/data/openssl/certs
touch ./examples/Docker/data/openssl-ca/issuer-crl.pem
cp issuer-cert.pem    ./examples/Docker/data/openssl-ca/
cp issuer-private.pem    ./examples/Docker/data/openssl-ca/
cp issuer.cnf    ./examples/Docker/data/openssl-ca/
cp cacert.pem    ./examples/Docker/data/openssl-ca/
```

Expected tree:
```
examples/Docker/data/openssl-ca/
├── cacert.pem
├── issuer-cert.pem
├── issuer.cnf
├── issuer-crl.pem
└── issuer-private.pem
```

---

## Configuration
Create `examples/Docker/data/est_proxy.cfg` with at least the following:

```ini
[DEFAULT]
debug = True
connection_log = True

[Daemon]
address = 0.0.0.0
port = 17443
key_file  = /usr/local/est_proxy/data/certs/est-srv.key.pem
cert_file = /usr/local/est_proxy/data/certs/est-srv.crt.pem

[main]
ca_handler = openssl
services = cacerts,simpleenroll,simplereenroll

[CAhandler]
handler_file     = examples.ca_handler.openssl_ca_handler

# ---- Required for enroll/reenroll ----
# If certificates are generated using only the Root CA, copy the CA certificate here
issuing_ca_key   = /usr/local/est_proxy/data/openssl-ca/issuer-private.pem
issuing_ca_cert  = /usr/local/est_proxy/data/openssl-ca/issuer-cert.pem
issuing_ca_crl   = /usr/local/est_proxy/data/openssl-ca/issuer-crl.pem

# Optional defaults
cert_validity_days = 365
cert_save_path     = /usr/local/est_proxy/data/openssl/certs

# If certificates are generated using only the Root CA, leave this field empty.
ca_cert_chain_list = ["/usr/local/est_proxy/data/openssl-ca/cacert.pem"]

# OpenSSL issuer profile (extensions)
# If certificates are generated using only the Root CA, use ca.cnf file here
openssl_conf = /usr/local/est_proxy/data/openssl-ca/issuer.cnf

whitelist = []
blacklist = []
save_cert_as_hex = true
```

---

## Run (Docker Compose)
From the repo root:
```bash
cd examples/Docker
```

Start:
```bash
docker compose up -d
```

---

## Verify
List containers and follow logs:
```bash
docker ps
docker logs -f est-proxy
```

Quick endpoint probe to verify the EST service is running correctly:
```bash
curl -vk https://localhost:8001/.well-known/est/cacerts
```

You should see a successful HTTPS response with a PKCS#7 payload.

---

# Deploy on a cloud host

### SSH to remote
```bash
ssh <user>@<host>    # or: ssh -i <key> <user>@<host>
```

### Prepare directory layout
```bash
mkdir -p ~/est-proxy-server/{data/certs,data/openssl/certs,data/openssl-ca}
cd ~/est-proxy-server
```

Copy over the same **server** and **issuer/CA** files used locally into `./data/...` paths.

Expected layout:
```
est-proxy-server/
├── data
│   ├── certs
│   │   ├── est-srv.crt.pem
│   │   └── est-srv.key.pem
│   ├── est_proxy.cfg
│   ├── openssl
│   │   └── certs
│   └── openssl-ca
│       ├── cacert.pem
│       ├── issuer-cert.pem
│       ├── issuer.cnf
│       ├── issuer-crl.pem
│       └── issuer-private.pem
└── docker-compose.yml
```

### Create `docker-compose.yml`
```yaml
services:
  est-proxy:
    image: DOCKERHUB_USER/est-proxy-server:TAG
    volumes:
      - type: bind
        source: ./data
        target: /usr/local/est_proxy/data
        read_only: false
      - type: bind
        source: /etc/timezone
        target: /etc/timezone
        read_only: true
      - type: bind
        source: /etc/localtime
        target: /etc/localtime
        read_only: true
    ports:
      - "8001:17443"
    restart: always
```
### Prepare [est_proxy.cfg](#configuration) file as defined in the configuration section above.

### Start and Verify
```bash
docker compose up -d
docker ps
docker logs -f est-proxy

# Local probe from the server to verify the EST service is running correctly:
curl -vk https://127.0.0.1:8001/.well-known/est/cacerts

# Remote probe from your workstation:
curl -vk https://<REMOTE_HOST>:8001/.well-known/est/cacerts
```

> Ensure your cloud firewall / security group allows inbound **TCP/8001** from your source IP(s), and that no other service is using that port.

---

## Troubleshooting
- **Handshake / chain errors**
  Confirm `est-srv.crt.pem` matches `est-srv.key.pem`, and that `ca_cert_chain_list` correctly references your root CA(s).
- **Enrollment fails**
  Check paths in `est_proxy.cfg` (`issuing_ca_*`, `openssl_conf`) and that `issuer-crl.pem` exists (can be empty file if CRL not used).
- **Permission errors**
  Verify mounted paths and file permissions: Docker must read the certs/keys inside the container.
- **Wrong port**
  Confirm `ports: "8001:17443"` and that you’re curling `https://<host>:8001/`.

---

## License
- Upstream: GPLv3 (grindsa/est_proxy)
- This repository: **AGPLv3**
