// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <string.h>
#include <qsc_encoding.h>

extern const qsc_encoding_t Dilithium_R3_4x4_encodings;
extern const qsc_encoding_t Dilithium_R3_6x5_encodings;
extern const qsc_encoding_t Dilithium_R3_8x7_encodings;

extern const qsc_encoding_t Dilithium_R3_4x4_AES_encodings;
extern const qsc_encoding_t Dilithium_R3_6x5_AES_encodings;
extern const qsc_encoding_t Dilithium_R3_8x7_AES_encodings;

extern const qsc_encoding_t Kyber512_encoding;
extern const qsc_encoding_t Kyber768_encoding;
extern const qsc_encoding_t Kyber1024_encoding;

extern const qsc_encoding_t FALCON_R3_512_encodings;
extern const qsc_encoding_t FALCON_R3_1024_encodings;

extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_128S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_192S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_256S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_128F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_128F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_128S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_128S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_192F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_192F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_192S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_192S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_256F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_256F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_256S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHA2_256S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_128F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_128F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_128S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_128S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_192F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_192F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_192S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_192S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_256F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_256F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_256S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_SHAKE_256S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_128F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_128F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_128S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_128S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_192F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_192F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_192S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_192S_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_256F_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_256F_SIMPLE_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_256S_ROBUST_encodings;
extern const qsc_encoding_t SPHINCSPLUS_R3_HARAKA_256S_SIMPLE_encodings;

static const qsc_encoding_t* qsc_encodings[] = {
    &Dilithium_R3_4x4_encodings,
    &Dilithium_R3_6x5_encodings,
    &Dilithium_R3_8x7_encodings,
    &Dilithium_R3_4x4_AES_encodings,
    &Dilithium_R3_6x5_AES_encodings,
    &Dilithium_R3_8x7_AES_encodings,
    &Kyber512_encoding,
    &Kyber768_encoding,
    &Kyber1024_encoding,
    &FALCON_R3_512_encodings,
    &FALCON_R3_1024_encodings,
    &SPHINCSPLUS_R3_SHA2_128S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_192S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_256S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_128F_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHA2_128F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_128S_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHA2_128S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_192F_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHA2_192F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_192S_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHA2_192S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_256F_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHA2_256F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHA2_256S_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHA2_256S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHAKE_128F_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHAKE_128F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHAKE_128S_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHAKE_128S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHAKE_192F_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHAKE_192F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHAKE_192S_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHAKE_192S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHAKE_256F_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHAKE_256F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_SHAKE_256S_ROBUST_encodings,
    &SPHINCSPLUS_R3_SHAKE_256S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_HARAKA_128F_ROBUST_encodings,
    &SPHINCSPLUS_R3_HARAKA_128F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_HARAKA_128S_ROBUST_encodings,
    &SPHINCSPLUS_R3_HARAKA_128S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_HARAKA_192F_ROBUST_encodings,
    &SPHINCSPLUS_R3_HARAKA_192F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_HARAKA_192S_ROBUST_encodings,
    &SPHINCSPLUS_R3_HARAKA_192S_SIMPLE_encodings,
    &SPHINCSPLUS_R3_HARAKA_256F_ROBUST_encodings,
    &SPHINCSPLUS_R3_HARAKA_256F_SIMPLE_encodings,
    &SPHINCSPLUS_R3_HARAKA_256S_ROBUST_encodings,
    &SPHINCSPLUS_R3_HARAKA_256S_SIMPLE_encodings
};

static int qsc_encoding_length = sizeof(qsc_encodings) / sizeof(qsc_encodings[0]);

QSC_RC qsc_encoding_by_name_oid(const qsc_encoding_t** ctx_enc, const qsc_encoding_impl_t** ctx_impl, const char* algorithm_name, const char* encoding_name) {
    const qsc_encoding_impl_t* res = 0;
    for (int i = 0; i < qsc_encoding_length; ++i) {
        const qsc_encoding_t* e = qsc_encodings[i];
        if (!strcmp(algorithm_name, e->algorithm_name) || !strncmp(algorithm_name, e->algorithm_oid_str, strlen(e->algorithm_oid_str))) {
            for (int j = 0; j < e->encodings_len; ++j) {
                const qsc_encoding_impl_t* impl = &e->encoding[j];
                if (!strcmp(encoding_name, impl->encoding_name)) {
                    *ctx_impl = impl;
                    *ctx_enc = e;
                    return QSC_ENC_OK;
                }
            }
        }
    }
    return QSC_ENC_ERR;
}

QSC_RC qsc_encode(const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_out, const unsigned char* pk, unsigned char** pkenc, const unsigned char* sk, unsigned char** skenc, int withoptional) {
    // Handle error cases
    if (!skenc && !pkenc)
        return QSC_ENC_ILLEGAL_INP;
    // RAW: PK not in SK, Encode PK in SK, encodeSK, pk or sk not provided
    if (!ctx->raw_private_key_encodes_public_key && withoptional && skenc && (!pk || !sk))
        return QSC_ENC_ILLEGAL_INP;
    // RAW: PK not in SK, Encode PK in SK, encodePK, pk not provided
    if (!ctx->raw_private_key_encodes_public_key && withoptional && pkenc && !pk)
        return QSC_ENC_ILLEGAL_INP;
    // RAW: PK not in SK, Don't encode PK in SK, encodeSK, sk not provided
    if (!ctx->raw_private_key_encodes_public_key && !withoptional && skenc && !sk)
        return QSC_ENC_ILLEGAL_INP;
    // RAW: PK not in SK, Don't encode PK in SK, encodePK, pk not provided
    if (!ctx->raw_private_key_encodes_public_key && !withoptional && pkenc && !pk)
        return QSC_ENC_ILLEGAL_INP;
    // RAW: PK in SK, encode PK in SK, encodeSK, sk not provided
    if (ctx->raw_private_key_encodes_public_key && withoptional && skenc && !sk)
        return QSC_ENC_ILLEGAL_INP;
    // RAW: PK in SK, don't encode PK in SK, encodeSK, sk not provided
    if (ctx->raw_private_key_encodes_public_key && !withoptional && skenc && !sk)
        return QSC_ENC_ILLEGAL_INP;
    
    
    return ctx_out->encode(ctx, ctx_out, pk, pkenc, sk, skenc, withoptional);
}

QSC_RC qsc_decode(const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_in, const unsigned char* pk, unsigned char** pkdec, const unsigned char* sk, unsigned char** skdec, int withoptional) {
    // Handle error cases
    if (!skdec && !pkdec)
        return QSC_ENC_ILLEGAL_INP;
    if (!ctx->raw_private_key_encodes_public_key && withoptional && skdec && !sk)
        return QSC_ENC_ILLEGAL_INP;
    if (!ctx->raw_private_key_encodes_public_key && !withoptional && skdec && !sk)
        return QSC_ENC_ILLEGAL_INP;
    if (!ctx->raw_private_key_encodes_public_key && !withoptional && pkdec && !pk)
        return QSC_ENC_ILLEGAL_INP;
    if (ctx->raw_private_key_encodes_public_key && withoptional && skdec && !sk)
        return QSC_ENC_ILLEGAL_INP;
    if (ctx->raw_private_key_encodes_public_key && !withoptional && skdec && (!sk || !pk))
        return QSC_ENC_ILLEGAL_INP;
    if (ctx->raw_private_key_encodes_public_key && !withoptional && pkdec && !pk)
        return QSC_ENC_ILLEGAL_INP;
    
    return ctx_in->decode(ctx, ctx_in, pk, pkdec, sk, skdec, withoptional);
}
