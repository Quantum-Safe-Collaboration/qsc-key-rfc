# qsc-key-encoder
QSC Key Encoder Library

This library supports encoding and decoding keys of the NIST PQC selected algorithms to P8 / SPKI structures as defined by the following internet-drafts:

- https://datatracker.ietf.org/doc/draft-uni-qsckeys-dilithium/00/
- https://datatracker.ietf.org/doc/draft-uni-qsckeys-falcon/00/
- https://datatracker.ietf.org/doc/draft-uni-qsckeys-kyber/00/
- https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/

## Encoding PKCS#8 PrivateKeyInfo and SubjectPublicKeyInfo

PrivateKeyInfo for PKCS#8 is specified in RFC5208:

```
   PrivateKeyInfo ::=  SEQUENCE {
       version               INTEGER             -- PKCS#8 syntax ver
       privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
       privateKey            OCTET STRING,       -- see chapter below
       attributes            [0]  IMPLICIT Attributes OPTIONAL
   }
```

The algorithm encodings differ in the ASN.1 structure that is wrapped in the `privateKey` OCTET STRING.


SubjectPublicKeyInfo (SPKI) is specified in RFC5280:

```
   SubjectPublicKeyInfo := SEQUENCE {
       algorithm          AlgorithmIdentifier  -- see chapter above
       subjectPublicKey   BIT STRING           -- see chapter below
   }
```

The algorithm encodings differ in the ASN.1 structure that is wrapped in the `subjectPublicKey` BIT STRING.

## API Use

An encoding context can be retrieved by specifying the algorithm and the encoding specification.

Example: retrieve an encoding context for `Dilithium2` according to `draft-uni-qsckeys-dilithium-00` for the PKCS#8 and SPKI structure:

```
const qsc_encoding_t* ctx = 0;
const qsc_encoding_impl_t* encoding = 0;

int ret = qsc_encoding_by_name_oid(&ctx, &encoding, "Dilithium2", "draft-uni-qsckeys-dilithium-00/p8-spki");
// alternatively by OID: qsc_encoding_by_name_oid(&ctx, &encoding, "1.3.6.1.4.1.2.267.7.4.4", "draft-uni-qsckeys-dilithium-00/p8-spki");
assert(ret == QSC_ENC_OK);
```

Alternatively, an encoder that encodes only the `privateKey` and `subjectPublicKey` part can be obtained with `draft-uni-qsckeys-dilithium-00/sk-pk`.

The available encoding strings are:

```
draft-uni-qsckeys-dilithium-00/p8-spki
draft-uni-qsckeys-dilithium-00/sk-pk
draft-uni-qsckeys-falcon-00/p8-spki
draft-uni-qsckeys-falcon-00/sk-pk
draft-uni-qsckeys-kyber-00/p8-spki
draft-uni-qsckeys-kyber-00/sk-pk
draft-uni-qsckeys-sphincsplus-00/p8-spki
draft-uni-qsckeys-sphincsplus-00/sk-pk
```

The input for the encoding API are the raw public/private keys as provided by the NIST PQC reference implementations. Use the `qsc_encode` API to output the encoding:

```
unsigned char* pkEnc = calloc(encoding->crypto_publickeybytes, 1);
unsigned char* skEnc = calloc(encoding->crypto_secretkeybytes, 1);

int ret = qsc_encode(ctx, encoding, pk, &pkEnc, sk, &skEnc, withoptional);
assert(ret == QSC_ENC_OK);
```

The `withoptional` parameter specifies if optional parts should be encoded (i.e. the OPTIONAL `publicKey` field in `privateKey`).

To decode to the raw public/private key format, use the `qsc_decode` API:

```
int ret = qsc_decode(ctx, encoding, pkEnc, &pk, skEnc, &sk, withoptional);
assert(ret == QSC_ENC_OK);
```
Again, the `withoptional` parameter specifies if the input was encoding with or without OPTIONAL components.

## Notes

Some NIST PQC algorithms include the public key in their raw private key format, some not:
Case 1) Kyber and SPHINCS+ contain the public key as part of their raw private keys.
Case 2) Dilithium and FALCON do not contain the public key as part of their raw private keys.

This has implications on some encoding cases:

- In case 1), the API is able to encode public key and private key by only prividing the raw private key. This is not possible in case 2).
- In case 2), if the encoded private key was created with the `withoptional = 0` option, the raw private key can be decoded only if both the encoded private key and public key is provided.
- If the encoded private key was created with the `withoptional = 1` option, both the raw private keys and public keys can always be reconstructed just by providing the encoded private key.

## Build and test

Prerequisites: cmake, gcc/clang, valgrind, asan (for testing).

Build:

```
mkdir -p build
cmake -B ./build -DCMAKE_BUILD_TYPE=<Debug/Release/ASAN>
cmake --build ./build --config
```

The regular test suite encodes the KAT provided by the NIST PQC submissions and decodes them again:

```
ctest
```

To run the tests with valgrind memcheck:
```
ctest -T memcheck
```
