/**
 * @file qsc_encoding.h
 * 
 * QSC encoding library.
 * 
 * @copyright Copyright (c) 2022 IBM Corp.
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ENCODINGS_H
#define ENCODINGS_H

#include <qsc_encoding.h>

/**
 * Encode to draft-uni-qsckeys-01 format.
 * 
 * @param[out] ctx_alg Algorithm context
 * @param[out] ctx_enc Encoding context
 * @param[in/out] pk Input public key.
 * @param[out] pkenc Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skenc Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
QSC_RC qsc_encode_draft_uni_qsckeys_01(const qsc_encoding_t* ctx_alg, const qsc_encoding_impl_t* ctx_enc, const unsigned char* pk, unsigned char** pkenc, const unsigned char* sk, unsigned char** skenc, int withoptional);

/**
 * Decode from draft-uni-qsckeys-01 format.
 * 
 * @param[out] ctx_alg Algorithm context
 * @param[out] ctx_enc Encoding context
 * @param[in/out] pk Input public key.
 * @param[out] pkdec Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skdec Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
QSC_RC qsc_decode_draft_uni_qsckeys_01(const qsc_encoding_t* ctx_alg, const qsc_encoding_impl_t* ctx_enc, const unsigned char* pk, unsigned char** pkdec, const unsigned char* sk, unsigned char** skdec, int withoptional);

/**
 * Encode to draft-uni-qsckeys-01 format.
 * For the private key, only the privateKey part of PublicKeyInfo.
 * For the public key, only the subjectPublicKey part of SubjectPublicKeyInfo.
 * 
 * @param[out] ctx_alg Algorithm context
 * @param[out] ctx_enc Encoding context
 * @param[in/out] pk Input public key.
 * @param[out] pkenc Output encoded public key. Must be pre-allocated, Output pointer may be assigned to the same address as the input pointer.
 * @param[in/out] sk Input private key.
 * @param[out] skenc Output encoded private key. Must be pre-allocated. Output pointer may be assigned to the same address as the input pointer.
 * @return Status code.
 */
QSC_RC qsc_encode_draft_uni_qsckeys_01_skpk(const qsc_encoding_t* ctx_alg, const qsc_encoding_impl_t* ctx_enc, const unsigned char* pk, unsigned char** pkenc, const unsigned char* sk, unsigned char** skenc, int withoptional);

#endif
