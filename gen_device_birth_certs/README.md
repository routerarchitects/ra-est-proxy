This module provides a scripted workflow to generate and manage **device birth certificates** for an EST Proxy Server demo.
It sets up a Root Certificate Authority (CA), generates server and client certificates, verifies them, and transfers them to a destination.

## 📂 Directory Layout
    gen_device_birth_certs/
    ├── 00_env.sh # Shared environment variables & helpers
    ├── 10_create_root_ca.sh # Generate Root CA key and certificate
    ├── 20_create_server_cert.sh # Generate server key and signed certificate
    ├── 21_create_client_cert.sh # Generate client key and signed certificate
    ├── 30_verify_certs.sh # Verify server/client certs against CA
    ├── 40_transfer_client.sh # Transfer client certs to destination
    └── conf/
    ├── client.cnf # OpenSSL config for client certs
    ├── root_ca.cnf # OpenSSL config for Root CA
    └── server.cnf # OpenSSL config for server certs

    Certificates are stored under a `certs/` folder (created automatically by script):

    certs/
    ├── rootca/
    │   ├── ca_key.pem
    │   └── ca_cert.pem
    ├── server/
    │ ├── server.key
    │ └── server.crt
    └── clients/
    ├── client-<id>.key
    └── client-<id>.crt

## ⚙️ Requirements

   - Linux/Unix shell with `bash`
   - [`openssl`](https://www.openssl.org/) installed and available in `$PATH`


## 🚀 Usage

### NOTE:
    If you create a new CA, Issuer, or Server certificate, make sure to update
    both server and client certificates accordingly. Failing to do so may result in TLS
    connection failures due to mismatched trust chains.

  #### Create Root CA certificates
     ./10_create_root_ca.sh

     Generates:
     certs/rootca/ca_key.pem
     certs/rootca/ca_cert.pem

  #### Create Server Certificates
     ./20_create_server_cert.sh

     Generates:
     certs/server/server.key
     certs/server/server.crt

  #### Create Client Certificate
     ./21_create_client_cert.sh <client_id>

     Example:
     ./21_create_client_cert.sh dc6279652f19

    Generates:
    certs/client-<client_id>.key
    certs/client-<clinet_id>.crt

    <client_id> must be a 12-character hex string (like a MAC address).

  #### Verify Certificates
     ./30_verify_certs.sh
     ./30_verify_certs.sh <client_id>

     Verifies server cert against CA
     Optionally verifies a specific client cert against CA
     Prints modulus checksums to confirm key/cert pair integrity

  #### Transfer Client Certs
     ./40_transfer_client.sh <client_id> <destination>

     Examples:

     Local copy:
     ./40_transfer_client.sh dc6279652f19 /tmp/ucentral

     Remote copy:
     ./40_transfer_client.sh dc6279652f19 root@200.20.20.107:/etc/ucentral

     Copies:
     key.pem → client key
     cert.pem → client cert
     insta.pem → CA cert

## 🔧 Configuration

   All OpenSSL configs are in the conf/

   directory:
   - root_ca.cnf → Distinguished name for Root CA
   - server.cnf → Distinguished name & extensions for server cert
   - client.cnf → Extensions for client certs (clientAuth)

   You can edit these files to adjust CN, O, OU, or extensions.


## 📌 Notes

  #### Default key sizes & validity:

   - Root CA: 4096 bits, 1 years (365 days)

   - Server/Client: 2048 bits, 1 years (365 days)

  #### Environment variables (can override before running scripts):

   - ROOT_BITS, LEAF_BITS

   - ROOT_DAYS, LEAF_DAYS

   Existing keys/certs are not overwritten unless manually deleted.
