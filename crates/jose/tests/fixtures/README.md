# Test fixtures

Keys used by the tests. They are test-only; never use them anywhere else. The tests do not
generate keys (except the key generation tests themselves). Generated with OpenSSL 3
(3.5.5 at the time of writing):

```sh
# Valid keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048.pem
openssl pkey -in rsa2048.pem -pubout -out rsa2048.pub.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es256.pem
openssl pkey -in es256.pem -pubout -out es256.pub.pem

# Rejected: modulus size (the 8192-bit private key is not kept)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1024.pem
openssl pkey -in rsa1024.pem -pubout -out rsa1024.pub.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:8192 | openssl pkey -pubout -out rsa8192.pub.pem

# Rejected: key type
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out es384.pem
openssl pkey -in es384.pem -pubout -out es384.pub.pem
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out rsa-pss.pem

# Rejected: PEM label
openssl pkey -in rsa2048.pem -traditional -out rsa2048.pkcs1.pem           # RSA PRIVATE KEY
openssl rsa -in rsa2048.pem -RSAPublicKey_out -out rsa2048.pkcs1.pub.pem   # RSA PUBLIC KEY
openssl pkcs8 -topk8 -in rsa2048.pem -v2 aes-256-cbc -passout pass:test -out rsa2048.enc.pem  # ENCRYPTED PRIVATE KEY
```

# Second ES256 key (a key other than es256.pem)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es256b.pem
openssl pkey -in es256b.pem -pubout -out es256b.pub.pem

# ES256 key whose public x or y coordinate starts with a 0x00 byte
# (repeat genpkey until `openssl pkey -in K -pubout -outform DER | tail -c 64 | xxd -p` has
# 00 at the start of x or y; the committed es256-zero.pem was found this way)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es256-zero.pem
openssl pkey -in es256-zero.pem -pubout -out es256-zero.pub.pem
