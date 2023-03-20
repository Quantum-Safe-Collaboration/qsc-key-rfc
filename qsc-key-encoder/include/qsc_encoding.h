/**
 * @file qsc_encoding.h
 * 
 * QSC encoding library.
 * 
 * @copyright Copyright (c) 2022 IBM Corp.
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef QSC_ENCODING_H
#define QSC_ENCODING_H

#include <stddef.h>

#define QSC_ENCODING_VERSION_STRING "draft-00-dev"

/**
 * Algorithm OIDs
 */
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x07\x04\x04"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x07\x06\x05"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x07\x08\x07"

#define QSC_ALGORITHM_SIG_DILITHIUM_R3_4x4_OID_STR "1.3.6.1.4.1.2.267.7.4.4"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_6x5_OID_STR "1.3.6.1.4.1.2.267.7.6.5"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_8x7_OID_STR "1.3.6.1.4.1.2.267.7.8.7"

#define QSC_ALGORITHM_SIG_DILITHIUM_R3_4x4_AES_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x0B\x04\x04"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_6x5_AES_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x0B\x06\x05"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_8x7_AES_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x0B\x08\x07"

#define QSC_ALGORITHM_SIG_DILITHIUM_R3_4x4_AES_OID_STR "1.3.6.1.4.1.2.267.11.4.4"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_6x5_AES_OID_STR "1.3.6.1.4.1.2.267.11.6.5"
#define QSC_ALGORITHM_SIG_DILITHIUM_R3_8x7_AES_OID_STR "1.3.6.1.4.1.2.267.11.8.7"

#define QSC_ALGORITHM_SIG_FALCON_R3_512_OID "\x06\x05" "\x2B\xCE\x0F\x03\x01"
#define QSC_ALGORITHM_SIG_FALCON_R3_1024_OID "\x06\x05" "\x2B\xCE\x0F\x03\x04"

#define QSC_ALGORITHM_SIG_FALCON_R3_512_OID_STR "1.3.9999.3.1"
#define QSC_ALGORITHM_SIG_FALCON_R3_1024_OID_STR "1.3.9999.3.4"

#define QSC_ALGORITHM_KEM_KYBER_768_R2_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x05\x03\x03"
#define QSC_ALGORITHM_KEM_KYBER_1024_R2_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x05\x04\x04"
#define QSC_ALGORITHM_KEM_KYBER_512_R3_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x08\x02\x02"
#define QSC_ALGORITHM_KEM_KYBER_768_R3_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x08\x03\x03"
#define QSC_ALGORITHM_KEM_KYBER_1024_R3_OID "\x06\x0b" "\x2b\x06\x01\x04\x01\x02\x82\x0b\x08\x04\x04"

#define QSC_ALGORITHM_KEM_KYBER_768_R2_OID_STR "1.3.6.1.4.1.2.267.5.3.3"
#define QSC_ALGORITHM_KEM_KYBER_1024_R2_OID_STR "1.3.6.1.4.1.2.267.5.4.4"
#define QSC_ALGORITHM_KEM_KYBER_512_R3_OID_STR "1.3.6.1.4.1.2.267.8.2.2"
#define QSC_ALGORITHM_KEM_KYBER_768_R3_OID_STR "1.3.6.1.4.1.2.267.8.3.3"
#define QSC_ALGORITHM_KEM_KYBER_1024_R3_OID_STR "1.3.6.1.4.1.2.267.8.4.4"

#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x04\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x04\x04"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x04\x07"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x04\x0A"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x05\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x05\x03"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x05\x05"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x05\x07"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x06\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x06\x03"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x06\x05"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x06\x07"

#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128F_ROBUST_OID_STR "1.3.9999.6.4.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128F_SIMPLE_OID_STR "1.3.9999.6.4.4"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128S_ROBUST_OID_STR "1.3.9999.6.4.7"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_128S_SIMPLE_OID_STR "1.3.9999.6.4.10"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192F_ROBUST_OID_STR "1.3.9999.6.5.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192F_SIMPLE_OID_STR "1.3.9999.6.5.3"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192S_ROBUST_OID_STR "1.3.9999.6.5.5"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_192S_SIMPLE_OID_STR "1.3.9999.6.5.7"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256F_ROBUST_OID_STR "1.3.9999.6.6.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256F_SIMPLE_OID_STR "1.3.9999.6.6.3"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256S_ROBUST_OID_STR "1.3.9999.6.6.5"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHA2_256S_SIMPLE_OID_STR "1.3.9999.6.6.7"

#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x07\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x07\x04"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x07\x07"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x07\x0A"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x08\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x08\x03"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x08\x05"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x08\x07"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x09\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x09\x03"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x09\x05"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x09\x07"

#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128F_ROBUST_OID_STR "1.3.9999.6.7.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128F_SIMPLE_OID_STR "1.3.9999.6.7.4"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128S_ROBUST_OID_STR "1.3.9999.6.7.7"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_128S_SIMPLE_OID_STR "1.3.9999.6.7.10"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192F_ROBUST_OID_STR "1.3.9999.6.8.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192F_SIMPLE_OID_STR "1.3.9999.6.8.3"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192S_ROBUST_OID_STR "1.3.9999.6.8.5"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_192S_SIMPLE_OID_STR "1.3.9999.6.8.7"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256F_ROBUST_OID_STR "1.3.9999.6.9.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256F_SIMPLE_OID_STR "1.3.9999.6.9.3"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256S_ROBUST_OID_STR "1.3.9999.6.9.5"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_SHAKE_256S_SIMPLE_OID_STR "1.3.9999.6.9.7"

#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x01\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x01\x04"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x01\x07"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x01\x0A"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x02\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x02\x03"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x02\x05"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x02\x07"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256F_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x03\x01"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256F_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x03\x03"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256S_ROBUST_OID "\x06\x06" "\x2B\xCE\x0F\x06\x03\x05"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256S_SIMPLE_OID "\x06\x06" "\x2B\xCE\x0F\x06\x03\x07"

#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128F_ROBUST_OID_STR "1.3.9999.6.1.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128F_SIMPLE_OID_STR "1.3.9999.6.1.4"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128S_ROBUST_OID_STR "1.3.9999.6.1.7"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_128S_SIMPLE_OID_STR "1.3.9999.6.1.10"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192F_ROBUST_OID_STR "1.3.9999.6.2.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192F_SIMPLE_OID_STR "1.3.9999.6.2.3"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192S_ROBUST_OID_STR "1.3.9999.6.2.5"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_192S_SIMPLE_OID_STR "1.3.9999.6.2.7"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256F_ROBUST_OID_STR "1.3.9999.6.3.1"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256F_SIMPLE_OID_STR "1.3.9999.6.3.3"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256S_ROBUST_OID_STR "1.3.9999.6.3.5"
#define QSC_ALGORITHM_SIG_SPHINCSPLUS_R3_HARAKA_256S_SIMPLE_OID_STR "1.3.9999.6.3.7"

/**
 * ASN.1 tags
 */
#define QSC_ASN1_SEQUENCE     0x30
#define QSC_ASN1_BITSTRING    0x03
#define QSC_ASN1_OCTETSTRING  0x04
#define QSC_ASN1_NULL         0x05
#define QSC_ASN1_INT          0x02
#define QSC_ASN1_OID          0x06
#define QSC_ASN_NULL_BYTES    2

#define QSC_ASN_TLLEN(len) (len < 0x80 ? 2 : (len < 0x10000 ? 4 : 5)) // max 3 bytes lengths.
#define QSC_ASN_OIDLEN(oid) (sizeof(oid)-1)

typedef struct qsc_asntl_t qsc_asntl_t;
typedef struct qsc_encoding_t qsc_encoding_t;
typedef struct qsc_encoding_impl_t qsc_encoding_impl_t;

/**
 * ASN.1 specific structure
 */
struct qsc_asntl_t {
    // ASN.1 tag
    int asntag;

    // ASN.1 length
    int asnlen;

    // ASN.1 single-byte value
    char asnvalue;

    // Mask provided for further encoding/decoding control
    unsigned char asnenc_flag;
    unsigned char asndec_flag;

    // Indicates during encoding that this element originates from the raw public key
    int encpub;
};

/**
 * Error codes
 */
typedef enum {
    QSC_ENC_OK          =   0,
    QSC_ENC_ERR         =  -1, /* generic error */
    QSC_ENC_ILLEGAL_INP =  -2,
} QSC_RC;

/**
 * Structure for QSC encodings
 */
struct qsc_encoding_t {
    const char* algorithm_name;
    const char* algorithm_oid_str;
    const char* oqs_name;

    int encodings_len;
    const qsc_encoding_impl_t* encoding;

    // Size of raw public key
    size_t raw_crypto_publickeybytes;
    // Size of raw private key
    size_t raw_crypto_secretkeybytes;

    // Note: not used
    //size_t raw_crypto_ciphertextbytes;
    //size_t raw_crypto_bytes;

    int raw_private_key_encodes_public_key;

    // Size of constant header bytes in raw public key
    size_t raw_crypto_publickey_header_bytes;
    // Header bytes of raw public key
    const unsigned char* raw_crypto_publickey_header;

    // Size of constant header bytes in raw private key
    size_t raw_crypto_secretkey_header_bytes;
    // Header bytes of raw public key
    const unsigned char* raw_crypto_secretkey_header;
};

/**
 * Structure for encoding implementations.
 */
struct qsc_encoding_impl_t {

    const char* algorithm_oid;
    const char* encoding_name;

    // Size of encoded public key
    size_t crypto_publickeybytes;
    // Size of encoded private key
    size_t crypto_secretkeybytes;

    // Size of encoded public key, without optional elements
    size_t crypto_publickeybytes_nooptional;

    // Size of encoded private key, without opional elements
    size_t crypto_secretkeybytes_nooptional;

    // Note: not used at the moment
    size_t crypto_ciphertextbytes;
    size_t crypto_bytes;

    // Size of PublicKey ASN.1 structure
    int pk_asntl_len;

    // Size of PrivateKey ASN.1 structure
    int sk_asntl_len;

    // PublicKey ASN.1 structure
    const qsc_asntl_t* pk_asntl;

    // PrivateKey ASN.1 structure
    const qsc_asntl_t* sk_asntl;

    // Encode function pointer
    int (*encode) (const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_in, const unsigned char* pk, unsigned char** pkenc, const unsigned char* sk, unsigned char** skenc, int withoptional);

    // Decode function pointer
    int (*decode) (const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_in, const unsigned char* pk, unsigned char** pkdec, const unsigned char* sk, unsigned char** skdec, int withoptional);

};

/**
 * Get QSC encoding structure by algorithm name/oid and encoding name
 * 
 * @param[out] ctx_alg Algorithm context
 * @param[out] ctx_enc Encoding context
 * @param[in] algorithm_name Algorithm name
 * @param[in] encoding_name Encoding name
 * @return QSC_RC return code
 */
QSC_RC qsc_encoding_by_name_oid(const qsc_encoding_t** ctx_alg, const qsc_encoding_impl_t** ctx_enc, const char* algorithm_name_oid, const char* encoding_name);

/**
 * Encoding function
 * 
 * @param[out] ctx_alg Algorithm context
 * @param[out] ctx_enc Encoding context
 * @param[in] pk Raw public key, may be NULL 
 * @param[out] pkenc Encoded public key
 * @param[in] sk Raw private key, may be NULL
 * @param[out] skenc Encoded private key
 * @return QSC_RC return code
 */
QSC_RC qsc_encode(const qsc_encoding_t* ctx_alg, const qsc_encoding_impl_t* ctx_enc, const unsigned char* pk, unsigned char** pkenc, const unsigned char* sk, unsigned char** skenc, int withoptional);

/**
 * Decoding function
 * 
 * @param[out] ctx_alg Algorithm context
 * @param[out] ctx_enc Encoding context
 * @param[in] pk Encoded public key, may be NULL
 * @param[out] pkdec Raw public key
 * @param[in] sk Encoded private key, may be NULL
 * @param[out] skdec Raw private key
 * @return QSC_RC return code
 */
QSC_RC qsc_decode(const qsc_encoding_t* ctx_alg, const qsc_encoding_impl_t* ctx_enc, const unsigned char* pk, unsigned char** pkdec, const unsigned char* sk, unsigned char** skdec, int withoptional);

#endif // QSC_ENCODING_H
