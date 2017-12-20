#!/bin/bash

set -ex

rm -f ./test.db

./build/linux-amd64/simpleca -config ./test_config.yaml createroot -name "Honest Achmed's Used Cars and Certificates" -crypto ecdsa:p256 -digest sha256 -validity 3650 honest-achmed
./build/linux-amd64/simpleca -config ./test_config.yaml createsub -issuer honest-achmed -name "Equally-Honest Mustafa" -crypto ecdsa:p256 -digest sha256 -validity 1825 honest-achmed-intermediate
./build/linux-amd64/simpleca -config ./test_config.yaml issue -issuer honest-achmed-intermediate -server -name "*.google.com" -altnames "google.com,google.cn,*.google.cn" -crypto ecdsa:p256 -digest sha256 -validity 365 wildcard-google-com
./build/linux-amd64/simpleca -config ./test_config.yaml export cert/wildcard-google-com | openssl x509 -noout -text | grep 'Not'
sleep 5
./build/linux-amd64/simpleca -config ./test_config.yaml renew -validity 365 wildcard-google-com
./build/linux-amd64/simpleca -config ./test_config.yaml export cert/wildcard-google-com | openssl x509 -noout -text | grep 'Not'
./build/linux-amd64/simpleca -config ./test_config.yaml revoke wildcard-google-com | openssl crl -noout -text -inform DER

# Test issuing from a revoked CA
./build/linux-amd64/simpleca -config ./test_config.yaml revoke honest-achmed-intermediate | openssl crl -noout -text -inform DER
if ./build/linux-amd64/simpleca -config ./test_config.yaml issue -issuer honest-achmed-intermediate -server -name "*.microsoft.com" -altnames "microsoft.com,microsoft.cn,*.microsoft.cn" -crypto ecdsa:p256 -digest sha256 -validity 365 wildcard-microsoft-com; then
    echo 'Uh oh!  That should have failed!'
    exit 1
fi
