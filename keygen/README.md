# Offline Key Accounting

Authorization is shared between the sev-shim and an external authorization provider. The only shared data (not a secret) is the public key of the API key signer. To require authorization and optionally enable rate limiting, set the `api-signer-public-key` option to the public key of the API key signer.
