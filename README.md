# pwnedkeys

[![GoDoc](https://godoc.org/github.com/adamdecaf/pwnedkeys?status.svg)](https://godoc.org/github.com/adamdecaf/pwnedkeys)
[![Build Status](https://travis-ci.com/adamdecaf/pwnedkeys.svg?branch=master)](https://travis-ci.com/adamdecaf/pwnedkeys)
[![Coverage Status](https://codecov.io/gh/adamdecaf/pwnedkeys/branch/master/graph/badge.svg)](https://codecov.io/gh/adamdecaf/pwnedkeys)
[![Go Report Card](https://goreportcard.com/badge/github.com/adamdecaf/pwnedkeys)](https://goreportcard.com/report/github.com/adamdecaf/pwnedkeys)
[![Apache 2 licensed](https://img.shields.io/badge/license-Apache2-blue.svg)](https://raw.githubusercontent.com/adamdecaf/pwnedkeys/master/LICENSE)

Package `github.com/adamdecaf/pwnedkeys` looks up Certificates, Certificate requests, Keys, etc in the pwnedkeys.com database.

## Usage

Pull the project down into an existing project:

```
$ go get -u github.com/adamdecaf/pwnedkeys
```

Then, use the library in your existing code:

```go
cert, err := parsePEM(certBytes)
if err != nil {
     // do something with the error
}
if err := pwnedkeys.CheckCertificate(http.DefaultClient, cert); err != nil { // Use a different http.Client
    // reject key/cert
}
```

## Getting Help

Feel free to [open a GitHub issue](https://github.com/adamdecaf/pwnedkeys/issues/new) for bug reports, feature requests, or questions. I'll do my best to answer them.

## Supported and Tested Platforms

- 64-bit Linux (Ubuntu, Debian), macOS

## Contributing

Yes please! Please createn an issue or submit a Pull Request towards the project!

Note: This project uses Go Modules, but only the Go standard library is used. Go 1.11 is required for modules, but this library should work with older Go releases.

## License

Apache License 2.0 See [LICENSE](LICENSE) for details.
