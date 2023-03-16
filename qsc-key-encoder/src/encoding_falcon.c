// SPDX-License-Identifier: Apache-2.0
#include <qsc_encoding.h>
#include <string.h>
#include "encodings.h"

#define FALCON_R3_512_CRYPTO_PUBLICKEYBYTES (896 + 1)
#define FALCON_R3_512_CRYPTO_SECRETKEYBYTES (1280 + 1)

#define FALCON_R3_512_F  384
#define FALCON_R3_512_G  384
#define FALCON_R3_512_FF 512
#define FALCON_R3_512_H  896

#define FALCON_R3_1024_CRYPTO_PUBLICKEYBYTES (1792 + 1)
#define FALCON_R3_1024_CRYPTO_SECRETKEYBYTES (2304 + 1)

#define FALCON_R3_1024_F  640
#define FALCON_R3_1024_G  640
#define FALCON_R3_1024_FF 1024
#define FALCON_R3_1024_H  1792

//   FALCONPublicKey := SEQUENCE {
//       h           OCTET STRING       -- integer polynomial h
//   }
#define FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) \
  QSC_ASN_TLLEN(FALCON_##NAME##_CRYPTO_PUBLICKEYBYTES) + \
  QSC_ASN_TLLEN(FALCON_##NAME##_H) + FALCON_##NAME##_H

/**
 * @brief 
 * subjectPublicKeyInfo := SEQUENCE {
 *  algorithm          AlgorithmIdentifier  -- see chapter above
 *  subjectPublicKey   BIT STRING           -- see chapter below
 * }
 */
#define FALCONXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(NAME) \
  QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_FALCON_##NAME##_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_FALCON_##NAME##_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

//   FALCONPrivateKey ::= SEQUENCE {
//       version     INTEGER {v2(1)}    -- syntax version 2 (round 3)
//       f           OCTET STRING,      -- short integer polynomial f
//       g           OCTET STRING,      -- short integer polynomial g
//       f           OCTET STRING,      -- short integer polynomial F
//       publicKey   [0] IMPLICIT FALCONPublicKey  OPTIONAL
//                                      -- see next section
//   }
#define FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) \
  QSC_ASN_TLLEN(FALCON_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(FALCON_##NAME##_F) + FALCON_##NAME##_F + \
  QSC_ASN_TLLEN(FALCON_##NAME##_G) + FALCON_##NAME##_G + \
  QSC_ASN_TLLEN(FALCON_##NAME##_FF) + FALCON_##NAME##_FF + \
  FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

#define FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME) \
  QSC_ASN_TLLEN(FALCON_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(FALCON_##NAME##_F) + FALCON_##NAME##_F + \
  QSC_ASN_TLLEN(FALCON_##NAME##_G) + FALCON_##NAME##_G + \
  QSC_ASN_TLLEN(FALCON_##NAME##_FF) + FALCON_##NAME##_FF

  /**
 * @brief 
 * PrivateKeyInfo ::=  SEQUENCE {
 *   version               INTEGER             -- PKCS#8 syntax ver
 *   privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *   privateKey            OCTET STRING,       -- see chapter below
 *   attributes            [0]  IMPLICIT Attributes OPTIONAL
 * }
 */
#define FALCONXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(NAME) \
  QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_FALCON_##NAME##_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_FALCON_##NAME##_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)

#define FALCONXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(NAME) \
  QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_FALCON_##NAME##_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_FALCON_##NAME##_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)

#define FALCONXXX_asntlp_pk_len 2

#define FALCON_ASNTLP_PK(NAME) \
  static const qsc_asntl_t FALCON_##NAME##_asntlp_pk[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asnenc_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = FALCON_##NAME##_H, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      } \
  };

FALCON_ASNTLP_PK(R3_512);
FALCON_ASNTLP_PK(R3_1024);

#define FALCONXXX_asntlp_sk_len 7

//   FALCONPrivateKey ::= SEQUENCE {
//       version     INTEGER {v2(1)}    -- syntax version 2 (round 3)
//       f           OCTET STRING,      -- short integer polynomial f
//       g           OCTET STRING,      -- short integer polynomial g
//       f           OCTET STRING,      -- short integer polynomial F
//       publicKey   [0] IMPLICIT FALCONPublicKey  OPTIONAL
//                                      -- see next section
//   }
#define FALCON_ASNTLP_SK(NAME) \
  static const qsc_asntl_t FALCON_##NAME##_asntlp_sk[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)), \
          .asnenc_flag = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asnenc_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = FALCON_##NAME##_F, \
          .asndec_flag = 1, \
          .asnenc_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = FALCON_##NAME##_G, \
          .asndec_flag = 1, \
          .asnenc_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = FALCON_##NAME##_FF, \
          .asndec_flag = 1, \
          .asnenc_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - QSC_ASN_TLLEN(FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asnenc_flag = 2 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = FALCON_##NAME##_H, \
          .asnenc_flag = 2, \
          .asndec_flag = 2, \
          .encpub = 1, \
      } \
  };

FALCON_ASNTLP_SK(R3_512);
FALCON_ASNTLP_SK(R3_1024);

static const qsc_encoding_impl_t Falcon_R3_512_encodings_arr[] = {
        {
            .encoding_name = "draft-uni-qsckeys-falcon-00/p8-spki", // ASN.1
            .algorithm_oid = QSC_ALGORITHM_SIG_FALCON_R3_512_OID,
            .crypto_publickeybytes = FALCONXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_512),
            .crypto_secretkeybytes = FALCONXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(R3_512),
            .crypto_publickeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_512),
            .crypto_secretkeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(R3_512),
            .crypto_bytes = 0,
            .pk_asntl_len = FALCONXXX_asntlp_pk_len,
            .pk_asntl = FALCON_R3_512_asntlp_pk,
            .sk_asntl_len = FALCONXXX_asntlp_sk_len,
            .sk_asntl = FALCON_R3_512_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "draft-uni-qsckeys-falcon-00/sk-pk", // ASN.1 without P8 / SPKI envelope
            .algorithm_oid = QSC_ALGORITHM_SIG_FALCON_R3_512_OID,
            .crypto_publickeybytes = FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_512),
            .crypto_secretkeybytes = FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(R3_512),
            .crypto_publickeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_512),
            .crypto_secretkeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(R3_512),
            .crypto_bytes = 0,
            .pk_asntl_len = FALCONXXX_asntlp_pk_len,
            .pk_asntl = FALCON_R3_512_asntlp_pk,
            .sk_asntl_len = FALCONXXX_asntlp_sk_len,
            .sk_asntl = FALCON_R3_512_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01_skpk,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
};

static const qsc_encoding_impl_t Falcon_R3_1024_encodings_arr[] = {
        {
            .encoding_name = "draft-uni-qsckeys-falcon-00/p8-spki", // ASN.1
            .algorithm_oid = QSC_ALGORITHM_SIG_FALCON_R3_1024_OID,
            .crypto_publickeybytes = FALCONXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_1024),
            .crypto_secretkeybytes = FALCONXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(R3_1024),
            .crypto_publickeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(R3_1024),
            .crypto_secretkeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(R3_1024),
            .crypto_bytes = 0,
            .pk_asntl_len = FALCONXXX_asntlp_pk_len,
            .pk_asntl = FALCON_R3_1024_asntlp_pk,
            .sk_asntl_len = FALCONXXX_asntlp_sk_len,
            .sk_asntl = FALCON_R3_1024_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "draft-uni-qsckeys-falcon-00/sk-pk", // ASN.1 without P8 / SPKI envelope
            .algorithm_oid = QSC_ALGORITHM_SIG_FALCON_R3_1024_OID,
            .crypto_publickeybytes = FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_1024),
            .crypto_secretkeybytes = FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES(R3_1024),
            .crypto_publickeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_PUBLICKEYBYTES(R3_1024),
            .crypto_secretkeybytes_nooptional = FALCONXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(R3_1024),
            .crypto_bytes = 0,
            .pk_asntl_len = FALCONXXX_asntlp_pk_len,
            .pk_asntl = FALCON_R3_1024_asntlp_pk,
            .sk_asntl_len = FALCONXXX_asntlp_sk_len,
            .sk_asntl = FALCON_R3_1024_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01_skpk,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
};

static const unsigned char FALCON_R3_512_publickey_header = 0x00 + 9;
static const unsigned char FALCON_R3_512_secretkey_header = 0x50 + 9;

static const unsigned char FALCON_R3_1024_publickey_header = 0x00 + 10;
static const unsigned char FALCON_R3_1024_secretkey_header = 0x50 + 10;

const qsc_encoding_t FALCON_R3_512_encodings = {
    .algorithm_name = "Falcon512",
    .algorithm_oid_str = QSC_ALGORITHM_SIG_FALCON_R3_512_OID_STR,
    .encodings_len = 2,
    .encoding = Falcon_R3_512_encodings_arr,
    .raw_crypto_publickeybytes = FALCON_R3_512_CRYPTO_PUBLICKEYBYTES,
    .raw_crypto_secretkeybytes = FALCON_R3_512_CRYPTO_SECRETKEYBYTES,
    .raw_crypto_publickey_header_bytes = 1,
    .raw_crypto_publickey_header = &FALCON_R3_512_publickey_header,
    .raw_crypto_secretkey_header_bytes = 1,
    .raw_crypto_secretkey_header = &FALCON_R3_512_secretkey_header,
    .raw_private_key_encodes_public_key = 0
};

const qsc_encoding_t FALCON_R3_1024_encodings = {
    .algorithm_name = "Falcon1024",
    .algorithm_oid_str = QSC_ALGORITHM_SIG_FALCON_R3_1024_OID_STR,
    .encodings_len = 2,
    .encoding = Falcon_R3_1024_encodings_arr,
    .raw_crypto_publickeybytes = FALCON_R3_1024_CRYPTO_PUBLICKEYBYTES,
    .raw_crypto_secretkeybytes = FALCON_R3_1024_CRYPTO_SECRETKEYBYTES,
    .raw_crypto_publickey_header_bytes = 1,
    .raw_crypto_publickey_header = &FALCON_R3_1024_publickey_header,
    .raw_crypto_secretkey_header_bytes = 1,
    .raw_crypto_secretkey_header = &FALCON_R3_1024_secretkey_header,
    .raw_private_key_encodes_public_key = 0
};
