// SPDX-License-Identifier: Apache-2.0
#include <qsc_encoding.h>
#include <string.h>
#include "encodings.h"

#define KYBER512_CRYPTO_PUBLICKEYBYTES 800
#define KYBER512_CRYPTO_SECRETKEYBYTES (800+832)

#define KYBER512_T   768
#define KYBER512_RHO 32
#define KYBER512_Z   32
#define KYBER512_S   768
#define KYBER512_HPK 32
#define KYBER512_D   32

#define KYBER768_CRYPTO_PUBLICKEYBYTES 1184
#define KYBER768_CRYPTO_SECRETKEYBYTES 2400

#define KYBER768_T   1152
#define KYBER768_RHO 32
#define KYBER768_Z   32
#define KYBER768_S   1152
#define KYBER768_HPK 32
#define KYBER768_D   32

#define KYBER1024_CRYPTO_PUBLICKEYBYTES 1568
#define KYBER1024_CRYPTO_SECRETKEYBYTES (1568+1600)

#define KYBER1024_T   1536
#define KYBER1024_RHO 32
#define KYBER1024_Z   32
#define KYBER1024_S   1536
#define KYBER1024_HPK 32
#define KYBER1024_D   32

// KyberPublicKey ::= SEQUENCE {
//   t           OCTET STRING,
//   rho         OCTET STRING
// }
#define KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) \
  QSC_ASN_TLLEN(KYBER##NAME##_CRYPTO_PUBLICKEYBYTES) + \
  QSC_ASN_TLLEN(KYBER##NAME##_T) + KYBER##NAME##_T + \
  QSC_ASN_TLLEN(KYBER##NAME##_RHO) + KYBER##NAME##_RHO


/**
 * @brief 
 * subjectPublicKeyInfo := SEQUENCE {
 *  algorithm          AlgorithmIdentifier  -- see chapter above
 *  subjectPublicKey   BIT STRING           -- see chapter below
 * }
 */
#define KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(NAME) \
  QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_KEM_KYBER_##NAME##_R3_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_KEM_KYBER_##NAME##_R3_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

// KyberPrivateKey ::= SEQUENCE {
//   Version     INTEGER {v0(0)}   -- version (round 3)
//   s           OCTET STRING,     -- sample s
//   PublicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
//                                 -- see next section
//   hpk         OCTET STRING      -- H(pk)
//   nonce       OCTET STRING,     -- z
// }
#define KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) \
  QSC_ASN_TLLEN(KYBER##NAME##_CRYPTO_SECRETKEYBYTES) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(KYBER##NAME##_S) + KYBER##NAME##_S + \
  KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) + \
  QSC_ASN_TLLEN(KYBER##NAME##_HPK) + KYBER##NAME##_HPK + \
  QSC_ASN_TLLEN(KYBER##NAME##_Z) + KYBER##NAME##_Z

#define KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME) \
  QSC_ASN_TLLEN(KYBER##NAME##_CRYPTO_SECRETKEYBYTES) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(KYBER##NAME##_S) + KYBER##NAME##_S + \
  QSC_ASN_TLLEN(KYBER##NAME##_HPK) + KYBER##NAME##_HPK + \
  QSC_ASN_TLLEN(KYBER##NAME##_Z) + KYBER##NAME##_Z

  /**
 * @brief 
 * PrivateKeyInfo ::=  SEQUENCE {
 *   version               INTEGER             -- PKCS#8 syntax ver
 *   privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *   privateKey            OCTET STRING,       -- see chapter below
 *   attributes            [0]  IMPLICIT Attributes OPTIONAL
 * }
 */
#define KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(NAME) \
  QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_KEM_KYBER_##NAME##_R3_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_KEM_KYBER_##NAME##_R3_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)

#define KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(NAME) \
  QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_KEM_KYBER_##NAME##_R3_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_KEM_KYBER_##NAME##_R3_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)

#define KyberXXX_asntlp_pk_len 3

#define KYBER_ASNTLP_PK(NAME) \
  static const qsc_asntl_t Kyber##NAME##_asntlp_pk[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - QSC_ASN_TLLEN(KYBER##NAME##_CRYPTO_PUBLICKEYBYTES), \
          .asnenc_flag = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_T, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_RHO, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      } \
  };

KYBER_ASNTLP_PK(512);
KYBER_ASNTLP_PK(768);
KYBER_ASNTLP_PK(1024);

#define KyberXXX_asntlp_sk_len 8

// KyberPrivateKey ::= SEQUENCE {
//   Version     INTEGER {v0(0)}   -- version (round 3)
//   s           OCTET STRING,     -- sample s
//   PublicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
//                                 -- see next section
//   hpk         OCTET STRING      -- H(pk)
//   nonce       OCTET STRING,     -- z
// }
#define KYBER_ASNTLP_SK(NAME) \
  static const qsc_asntl_t Kyber##NAME##_asntlp_sk[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)), \
          .asnenc_flag = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
          .asnenc_flag = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_S, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asnenc_flag = 2, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_T, \
          .asnenc_flag = 2, \
          .asndec_flag = 3, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_RHO, \
          .asnenc_flag = 2, \
          .asndec_flag = 3, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_HPK, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_Z, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      } \
  };

KYBER_ASNTLP_SK(512);
KYBER_ASNTLP_SK(768);
KYBER_ASNTLP_SK(1024);

#define KYBER_ASNTLP_SK_PARTIAL(NAME) \
  static const qsc_asntl_t Kyber##NAME##_asntlp_sk_partial[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - QSC_ASN_TLLEN(KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) \
      }, \
      { \
          .asntag = QSC_ASN1_INT, \
          .asnlen = 1, \
          .asnvalue = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = KYBER##NAME##_D \
      }, \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = 4 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = 0 \
      }, \
  };

KYBER_ASNTLP_SK_PARTIAL(512);
KYBER_ASNTLP_SK_PARTIAL(768);
KYBER_ASNTLP_SK_PARTIAL(1024);

static const qsc_encoding_impl_t Kyber512_encoding_arr[] = {
        {
            .encoding_name = "draft-uni-qsckeys-kyber-00/p8-spki", // ASN.1
            .algorithm_oid = QSC_ALGORITHM_KEM_KYBER_512_R3_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(512),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(512),
            .crypto_publickeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(512),
            .crypto_secretkeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(512),
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber512_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber512_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "draft-uni-qsckeys-kyber-00/sk-pk", // ASN.1 without P8 / SPKI envelope
            .algorithm_oid = QSC_ALGORITHM_KEM_KYBER_512_R3_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(512),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(512),
            .crypto_publickeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(512),
            .crypto_secretkeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(512),
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber512_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber512_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01_skpk,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
};

static const qsc_encoding_impl_t Kyber768_encoding_arr[] = {
        {
            .encoding_name = "draft-uni-qsckeys-kyber-00/p8-spki", // ASN.1
            .algorithm_oid = QSC_ALGORITHM_KEM_KYBER_768_R3_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(768),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(768),
            .crypto_publickeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(768),
            .crypto_secretkeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(768),
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber768_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber768_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "draft-uni-qsckeys-kyber-00/sk-pk", // ASN.1 without P8 / SPKI envelope
            .algorithm_oid = QSC_ALGORITHM_KEM_KYBER_768_R3_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(768),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(768),
            .crypto_publickeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(768),
            .crypto_secretkeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(768),
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber768_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber768_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01_skpk,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
};

static const qsc_encoding_impl_t Kyber1024_encoding_arr[] = {
        {
            .encoding_name = "draft-uni-qsckeys-kyber-00/p8-spki", // ASN.1
            .algorithm_oid = QSC_ALGORITHM_KEM_KYBER_1024_R3_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(1024),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(1024),
            .crypto_publickeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(1024),
            .crypto_secretkeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(1024),
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber1024_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber1024_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
        {
            .encoding_name = "draft-uni-qsckeys-kyber-00/sk-pk", // ASN.1 without P8 / SPKI envelope
            .algorithm_oid = QSC_ALGORITHM_KEM_KYBER_1024_R3_OID,
            .crypto_publickeybytes = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(1024),
            .crypto_secretkeybytes = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES(1024),
            .crypto_publickeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_PUBLICKEYBYTES(1024),
            .crypto_secretkeybytes_nooptional = KYBERXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(1024),
            .pk_asntl_len = KyberXXX_asntlp_pk_len,
            .pk_asntl = Kyber1024_asntlp_pk,
            .sk_asntl_len = KyberXXX_asntlp_sk_len,
            .sk_asntl = Kyber1024_asntlp_sk,
            .encode = qsc_encode_draft_uni_qsckeys_01_skpk,
            .decode = qsc_decode_draft_uni_qsckeys_01
        },
};

const qsc_encoding_t Kyber512_encoding = {
    .algorithm_name = "kyber512",
    .algorithm_oid_str = QSC_ALGORITHM_KEM_KYBER_512_R3_OID_STR,
    .encodings_len = sizeof(Kyber512_encoding_arr) / sizeof(Kyber512_encoding_arr[0]),
    .encoding = Kyber512_encoding_arr,
    .raw_crypto_publickeybytes = KYBER512_CRYPTO_PUBLICKEYBYTES,
    .raw_crypto_secretkeybytes = KYBER512_CRYPTO_SECRETKEYBYTES,
    .raw_private_key_encodes_public_key = 1
};

const qsc_encoding_t Kyber768_encoding = {
    .algorithm_name = "kyber768",
    .algorithm_oid_str = QSC_ALGORITHM_KEM_KYBER_768_R3_OID_STR,
    .encodings_len = sizeof(Kyber768_encoding_arr) / sizeof(Kyber768_encoding_arr[0]),
    .encoding = Kyber768_encoding_arr,
    .raw_crypto_publickeybytes = KYBER768_CRYPTO_PUBLICKEYBYTES,
    .raw_crypto_secretkeybytes = KYBER768_CRYPTO_SECRETKEYBYTES,
    .raw_private_key_encodes_public_key = 1
};

const qsc_encoding_t Kyber1024_encoding = {
    .algorithm_name = "kyber1024",
    .algorithm_oid_str = QSC_ALGORITHM_KEM_KYBER_1024_R3_OID_STR,
    .encodings_len = sizeof(Kyber1024_encoding_arr) / sizeof(Kyber1024_encoding_arr[0]),
    .encoding = Kyber1024_encoding_arr,
    .raw_crypto_publickeybytes = KYBER1024_CRYPTO_PUBLICKEYBYTES,
    .raw_crypto_secretkeybytes = KYBER1024_CRYPTO_SECRETKEYBYTES,
    .raw_private_key_encodes_public_key = 1
};
