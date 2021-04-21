<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for XCA -->
# Support for an XCA based Certificate Authorities

This handler can be used to store, certificates and requests in an [XCA](https://github.com/chris2511/xca/) SQLite database.

It is also possible to fetch enrollment templates from XCA an apply them to certificate signing requests.

## Prerequisites

You need to have a ready-made xca database with CA certificate and keys imported. You further need the `Internal Name` from the Certificate Authorities to be used as show in the XCA application.

![xca-ca-list](xca-ca-list.png)

## Configuration

- place the XCA database into a directory which is accessible by `est_proxy`.

- modify the server configuration (`est_proxy.cfg`) and add the following parameters

```config
[CAhandler]
xdb_file: data/xca/est_proxy.xdb
issuing_ca_name: sub-ca
issuing_ca_key: sub-ca-key
passphrase: test1234
ca_cert_chain_list: ["root-ca"]
template_name: XCA template to be applied to CSRs
```

- `xdb_file` - path to XCA database
- `issuing_ca_key_passphrase` - password to access the private key
- `issuing_ca_name` - XCA name of the certificate authority used to issue certificates.
- `issuing_ca_key` - XCA name of the ley used to sign certificates. If not set same value as configured in `issuing_ca_name` will be assumed.
- `passphrase` - *optional* - passphrase to access the database and decrypt the private CA Key
- `ca_cert_chain_list` - *optional* - List of root and intermediate CA certificates to be added to the bundle return to an est-client (the issuing CA cert must not be included)
- `template_name` - *optional* - name of the XCA template to be applied during certificate issuance

Template support has been introduced starting from v0.13. Support is limited to the below parameters which can be applied during certificate issuance:

- Certificate validity (`validN`/`validM`)
- basicConstraints (`ca`)
- KeyUsage attributes (`keyUse`)
- extendedKeyUsage attributes (`eKeyUse`)
- crlDistributionPoints (`crlDist`)
- Enforcement of the following DN attributes:
  - OU: OrganizationalUnit
  - O: Organization
  - L: Locality
  - S: StateOrProvinceName
  - C: CountryName

Enjoy enrolling and revoking certificates...
