# simpleca

simpleca is a tool for managing an x.509 PKI without screwing around with OpenSSL config files or writing janky scripts to manage said config files.

## What does it do?

```
$ simpleca createroot -name "Honest Achmed's Used Cars and Certificates" -crypto ecdsa:p256 -digest sha256 -validity 3650 honest-achmed
$ simpleca createsub -issuer honest-achmed -name "Equally-Honest Mustafa" -crypto ecdsa:p256 -digest sha256 -validity 1825 honest-achmed-intermediate
$ simpleca issue -issuer honest-achmed-intermediate -server -name "*.google.com" -altnames "google.com,google.cn,*.google.cn" -crypto ecdsa:p256 -digest sha256 -validity 365 wildcard-google-com
$ simpleca renew -validity 365 wildcard-google-com

$ simpleca export cert/honest-achmed
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
$ simpleca export key/honest-achmed
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
$ simpleca export -out wildcard_google_com.crt cert/wildcard-google-com

$ simpleca revoke -out complying-with-court-order.crl wildcard-google-com
```

## Configuration

```yaml
# All parameters are optional.

# Default: $HOME/.simpleca.db
db_file: /path/to/sqlite/file
cert_defaults:
  # Default: sha256
  # Options:
  # md5 (not recommended)
  # sha1 (not recommended)
  # sha256
  # sha384
  # sha512
  digest_algo: sha256
  # No default
  issuer: "honest-achmed-intermediate"
  # Default: 365
  expiration_days: 365
  # No default
  country_name: "US"
  # No default
  state_name: "NJ"
  # No default
  locality_name: "Newark"
  # No default
  organization_name: "Honest Achmed's Used Cars and Certificates"
  # No default
  organizational_unit_name: "Mustafa's Creaky Old Laptop"
  # No default
  email_address: "achmed@honestachmed.dyndns.org"
# Default: rsa:2048
# Options:
# rsa:1024 (not recommended)
# rsa:2048
# rsa:4096
# ecdsa:p224
# ecdsa:p256
# ecdsa:p384
# ecdsa:p521
default_crypto: "rsa:4096"
```

## License

License is GPLv3.
