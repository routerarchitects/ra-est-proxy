<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Configuration options for est_proxy -->
# est_proxy configuration

est_proxy will be configured by a global configuration which needs to be specified when starting the proxy.

```bash
grindsa@rlh:~# est_proxy -c  est_proxy.cfg
```

## configuration options for est_proxy

| Section | Option | Description | Values | default|
| :-------| :------| :-----------| :------| :------|
| `DEFAULT` | `debug`  | Debug mode| True/False| False|
| `ClientAuth` | `address` | listing IP of est_proxy | True/False | None|
| `ClientAuth` | `port` | listening port of est_proxy  | integer | 1443|
| `ClientAuth` | `key_file` | key file in pem format   | True/False | None|
| `ClientAuth` | `cert_file` | certifcate file in pem format  | Integer  |None |
| `CAhandler` | `handler_file` | path and name of ca_handler file to be loaded. If not specified `est_proxy/ca_handler.py` will be loaded | examples/ca_handler/openssl_hander.py | `est_proxy/ca_handler.py`|
| `Logging` | `log_format` | logging formatter | [logging.Formatter](https://docs.python.org/3/library/logging.html#logging.Formatter) | `'%(message)s'`|

The options for the `CAHandler` section depend on the CA handler.

Instructions for [Insta Certifier](certifier.md)

Instructions for [Microsoft Certification Authority Web Enrollment Service](mscertsrv.md)

Instructions for [XCA handler](xca.md)

Instructions for [Openssl based CA handler](openssl.md)
