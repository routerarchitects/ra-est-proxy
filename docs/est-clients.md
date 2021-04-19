<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Example commands for est clients -->
# Example commends of EST clients used for testing

The below commands are tailored for my environment and need to be modified.

## [cisco/libest](https://github.com/cisco/libest)

### set environment variable for pem bundle used to verify the server certificate

```bash
export EST_OPENSSL_CACERT=/root/est_clt/cacerts.pem
```

### Get CA-certificates

ClientAuth

```bash
root@rlh:~# /usr/local/est/bin/estclient -g  -s est-srv.bar.local -p 1443 -o /tmp -v
```

### Enrollment

```bash
root@rlh:~# /usr/local/est/bin/estclient -e  -s est-srv.bar.local -p 1443 -c est-clt.cert.pem -k est-clt.key.pem -o /tmp --common-name "foo-est.est" -v
```

### Reenrollment

```bash
root@rlh:~# /usr/local/est/bin/estclient -e  -s est-srv.bar.local -p 1443 -c est-clt.cert.pem -k est-clt.key.pem -o /tmp --pem-out  --common-name "foo-est.est" -v
```

## [globalsign/est](https://github.com/globalsign/est)

### Installation (requires Ubuntu 20.04 or later)

```bash
root@rlh:~# go get github.com/globalsign/est
root@rlh:~# go get -u github.com/globalsign/est/cmd/estclient
```

### Fetch CA-certificates

```bash
root@rlh:~#  ~/go/bin/estclient cacerts -server est-srv.bar.local:1443 -insecure -out /tmp/foo.pem
```

### generate CSR

```bash
root@rlh:~#  openssl genrsa 4096 > /tmp/key.pem
root@rlh:~#  ~/go/bin/estclient csr -key /tmp/key.pem -cn 'foo-global' -out /tmp/csr.pem
```

### Enrollment

```bash
root@rlh:~#  ~/go/bin/estclient enroll -server est-srv.bar.local:1443 -explicit /tmp/foo.pem -csr /tmp/csr.pem -out /tmp/cert.pem -certs /home/joern/data/certs/est-clt.cert.pem -key /home/joern/data/certs/est-clt.key.pem
```

### above commands used in [estclient docker image](https://hub.docker.com/r/grindsa/estclient)

```bash
root@rlh:~#  mkdir -p /tmp/certs
root@rlh:~#  (umask 000; openssl genrsa 2048 > /tmp/certs/2048.pem)
root@rlh:~#  cp /home/joern/data/certs/est-clt*.* /tmp/certs
root@rlh:~#  docker network create est
root@rlh:~#  docker run -v /tmp/certs:/tmp/certs --network est grindsa/estclient estclient.globalsign csr -key /tmp/certs/2048.pem -cn 'est-clt-2048' -out /tmp/certs/csr2048.pem
root@rlh:~#  docker run -v /tmp/certs:/tmp/certs --network est grindsa/estclient estclient.globalsign cacerts -server 192.168.14.1:1443 -insecure -out /tmp/certs/cacerts.pem
root@rlh:~#  docker run -v /tmp/certs:/tmp/certs --network est grindsa/estclient estclient.globalsign enroll -server 192.168.14.1:1443  -insecure -csr /tmp/certs/csr2048.pem -out /tmp/certs/cert-2048.pem -certs /tmp/certs/est-clt.cert.pem -key /tmp/certs/est-clt.key.pem
```


## curl

### Get CA-certificates
```bash
root@rlh:~# curl -X GET -k  https://est-srv.bar.local:1443/.well-known/est/cacerts
```

### Enrollment

ClientAuth

```bash
root@rlh:~# curl https://est-srv.bar.local:1443/.well-known/est/simpleenroll --key est-clt.key.pem --cert est-clt.cert.pem  --cacert cacerts.pem  --data-binary @csr.p10 -H "Content-Type: application/pkcs10" --verbose
```

Enrollment using chunked encoding

```bash
root@rlh:~# curl https://est-srv.bar.local:1443/.well-known/est/simpleenroll --key est-clt.key.pem --cert est-clt.cert.pem  --cacert cacerts.pem  --data-binary @csr.p10 -H "Content-Type: application/pkcs10" --header "Transfer-Encoding: chunked" --verbose
```

### Reenrollment

ClientAuth

```bash
root@rlh:~# curl https://est-srv.bar.local:1443/.well-known/est/simplereenroll --key est-clt.key.pem --cert est-clt.cert.pem  --cacert cacerts.pem  --data-binary @csr.p10 -H "Content-Type: application/pkcs10" --verbose
```
Renrollment using chunked encoding

```bash
root@rlh:~# curl https://est-srv.bar.local:1443/.well-known/est/simplereenroll --key est-clt.key.pem --cert est-clt.cert.pem  --cacert cacerts.pem  --data-binary @csr.p10 -H "Content-Type: application/pkcs10" --header "Transfer-Encoding: chunked" --verbose
```
