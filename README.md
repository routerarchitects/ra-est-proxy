<!-- markdownlint-disable  MD013 -->
# est_proxy

![GitHub release](https://img.shields.io/github/release/grindsa/est_proxy.svg)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/est_proxy/main.svg?label=last%20commit%20into%20main)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/est_proxy/devel.svg?label=last%20commit%20into%20devel)
<!-- [![codecov](https://codecov.io/gh/grindsa/est_proxy/branch/devel/graph/badge.svg)](https://codecov.io/gh/grindsa/est_proxy/branch/devel) -->
![Codecov main](https://img.shields.io/codecov/c/gh/grindsa/est_proxy/branch/main?label=test%20coverage%20main)
![Codecov devel](https://img.shields.io/codecov/c/gh/grindsa/est_proxy/branch/devel?label=test%20coverage%20devel)

est_proxy is development project to create an est protocol proxy. Main
intention is to provide est enrollment services on CA servers which do not support this
protocol. It consists of two libraries:

- est_proxy/*.py - a bunch of classes implementing est server functionality based
on [rfc7030](https://tools.ietf.org/html/rfc7030)
- ca_handler.py - interface towards CA server. The intention of this library
is to be modular that an [adaption to other CA servers](docs/ca_handler.md)
should be straight forward. As of today the following handlers are available:
  - [NetGuard Certificate Manager/Insta certifier](docs/certifier.md)
  - [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)
  - [Openssl](docs/openssl.md)
  - [XCA](docs/xca.md)

For more up-to-date information and further documentation, please visit the
project's home page at: [https://github.com/grindsa/est_proxy](https://github.com/grindsa/est_proxy)

## ChangeLog

Releasenotes and ChangLog can be found at [https://github.com/grindsa/est_proxy/releases](https://github.com/grindsa/est_proxy/releases)

## Disclaimer

Following est-clients are used for regular testing of server functionality

- [Cisco/libest](https://github.com/cisco/libest)
- [GlobalSign estclient](https://github.com/globalsign/est)
- [curl](https://curl.se/)

Other clients are on my list for later testing. In case you are bored, feel
free to test other client implementations and raise [issues](https://github.com/grindsa/est_proxy/issues/new)
if something does not work as expected.

[Command-line parameters used for testing](docs/est-clients.md)

I am not a professional developer. Keep this in mind while laughing about my
code and don’t forget to send patches.

## Project status

As of today `est_proxy` supports the below authentication functions of RFC7030:

- Certificate TLS Authentication [(Section 2.2.1)](https://tools.ietf.org/html/rfc7030#section-2.2.1)

The following call-flows are supported:

- Distribution of CA Certificates (cacerts) [(Section 4.1)](https://tools.ietf.org/html/rfc7030#section-4.1)
- Simple Enrollment of Clients (simpleenroll) [(Section 4.2.1)](https://tools.ietf.org/html/rfc7030#section-4.2.1)
- Simple Re-enrollment of Clients (simplereenroll) [(Section 4.2.2)](https://tools.ietf.org/html/rfc7030#section-4.2.2)

Additional functionality will be added over time. If you are badly missing a
certain feature please raise an [issue](https://github.com/grindsa/est_proxy/issues/new)
to let me know.

## Installation

The fastest and most convenient way to install `est_proxy` is to use docker containers.  There are ready made images available at [dockerhub](https://hub.docker.com/r/grindsa/est_proxy) and [ghcr.io](https://github.com/grindsa?tab=packages&ecosystem=container) as well as [instructions to build your own container](examples/Docker/).

A manual installation procedure will be added at a later stage of the project

## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on my code of
conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay
in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the GPLv3 - see the [LICENSE](LICENSE) file for details
