## Purpose
This guide explains how to deploy **est-proxy** using Docker **and** how to generate the Root CA, server, and client (“device birth”) certificates with the provided `gen_device_birth_certs/` scripts.

###  Clone the repository
```bash
git clone https://github.com/routerarchitects/ra-est-proxy.git
cd ra-est-proxy
```
### Generate Certificates

Before running the EST proxy server, verify that the required server certificates exist in the expected location:

```
$ tree examples/Docker/data/certs/
examples/Docker/data/certs/
├── est-srv.crt.pem
└── est-srv.key.pem
```
If these files are missing (for example, on a first-time deployment), you must generate them using the certificate generation module.For that,

Refer to the detailed instructions in **gen_device_birth_certs/README.md**
 for creating Root CA, server, and client certificates. Once the server certificates are sucessfully generated, copy them into the data directory.For that Run the following commands from the repository root (`~/ra-est-proxy`):

```
mkdir -p examples/Docker/data/certs/

cp gen_device_birth_certs/certs/server/server.crt examples/Docker/data/certs/est-srv.crt.pem

cp gen_device_birth_certs/certs/server/server.key examples/Docker/data/certs/est-srv.key.pem
```

### Generate Issuer/CA Certificates

Use the [OpenWiFi Certificate Generation Scripts](https://drive.google.com/file/d/1Z7yBtjPBd-N5AU5BH_E6OX-Y77WMmRsE/view) to generate the issuer/CA certificates that will be used by the **est_proxy server** for signing client certificates.

## Note:
 This tar archive contains scripts and configuration files to generate OpenWiFi-compatible
 certificates for both the client and server. A README file is included with step-by-step
 instructions.You can customize fields such as the Common Name (CN) as needed. Important: If
 you create a new CA, Issuer, or Server certificate, make sure to update both server and client certificates accordingly. Failing to do so may result in TLS connection failures due to mismatched
trust chains.

After generating the certificates, copy them into the `est_proxy` data directory using the following commands:

```bash
mkdir -p ./examples/Docker/data/openssl-ca
mkdir -p ./examples/Docker/data/openssl/certs
touch ./examples/Docker/data/openssl-ca/issuer-crl.pem

cp OpenWiFi_Certificate_Generation_Scripts/output/issuer/certs/issuer-cert.pem \
   ./examples/Docker/data/openssl-ca/

cp OpenWiFi_Certificate_Generation_Scripts/output/issuer/private/issuer-private.pem \
   ./examples/Docker/data/openssl-ca/

cp OpenWiFi_Certificate_Generation_Scripts/conf/issuer.cnf \
   ./examples/Docker/data/openssl-ca/

cp OpenWiFi_Certificate_Generation_Scripts/output/RootCA/certs/cacert.pem \
   ./examples/Docker/data/openssl-ca

$ tree examples/Docker/data/openssl-ca/
examples/Docker/data/openssl-ca/
├── issuer.cnf
├── issuer-crl.pem
├── issuer-cert.pem
├── issuer-private.pem
└── cacert.pem
```

### Run the container
From the directory containing the compose file:
```base
cd examples/Docker
docker-compose up
```
The compose maps container port 17443 to host port 8001:
- "Service URL: https://localhost:8001/"

#### How to check it’s running

- List containers
```base
   docker ps
```
- Check logs
```base
   docker logs -f est-proxy
```
- Quick endpoint probe
```base
   curl -X GET -k  https://localhost:8001/.well-known/est/cacerts
  ```
