# SEV-SNP Attestation Shim

A reverse proxy service that terminates TLS and exposes an AMD SEV-SNP attestation report over HTTP.

## Features

- TLS termination with automatic certificate management
- AMD SEV-SNP attestation endpoint
- API key validation through an external key server
- Rate limiting per API key
- Path-based access control

## Configuration

```yaml
domain: example.com                # Domain name for TLS certificate (leave empty to generate a self-signed certificate)
upstream-port: 8080                # Required: upstream HTTP port
metrics-port: 8081                 # Optional: Prometheus metrics port (disabled if empty)
listen-port: 443                   # Port to listen on (default: 443)
paths:                             # Optional: List of allowed paths (default: all)
  - /api/v1
  - /api/v2
key-server: http://localhost:8080  # Optional: URL of key validation server
staging-ca: false                  # Use Let's Encrypt staging environment
rate-limit: 1                      # Requests per second per API key
rate-burst: 2                      # Maximum burst size for rate limiting
verbose: true                      # Debug logging
```

## Attestation

The shim provides an attestation endpoint at `/.well-known/tinfoil-attestation` that returns a signed SEV-SNP attestation report.
The report includes a SHA-256 hash of the TLS certificate in the user data field, allowing clients to bind a TLS connection to an enclave measurement.

## Key Server and Ratelimiting

The `key-server` option can be set to the URL of a server that accepts an `Authorization` header and returns a 200 status code for valid keys, and anything else for invalid keys.
See [the example key server](https://github.com/tinfoilanalytics/sev-shim/blob/main/keyserver/main.go) for a simple implementation.

The `rate-limit` and `rate-burst` options can be used to limit the number of requests per second per API key.
