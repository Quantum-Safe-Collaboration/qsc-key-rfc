// SPDX-License-Identifier: Apache-2.0
#include <qsc_encoding.h>
#include <string.h>
#include "encodings.h"

// Note: the same sizes apply to SHAKE, HARAKA and "f" variants
#define SPHINCSPLUS_R3_128_CRYPTO_PUBLICKEYBYTES 32
#define SPHINCSPLUS_R3_128_CRYPTO_SECRETKEYBYTES 64
#define SPHINCSPLUS_R3_128_PKSEED 16
#define SPHINCSPLUS_R3_128_PKROOT 16
#define SPHINCSPLUS_R3_128_SKSEED 16
#define SPHINCSPLUS_R3_128_SKPRF  16

// Note: the same sizes apply to SHAKE, HARAKA and "f" variants
#define SPHINCSPLUS_R3_192_CRYPTO_PUBLICKEYBYTES 48
#define SPHINCSPLUS_R3_192_CRYPTO_SECRETKEYBYTES 96
#define SPHINCSPLUS_R3_192_PKSEED 24
#define SPHINCSPLUS_R3_192_PKROOT 24
#define SPHINCSPLUS_R3_192_SKSEED 24
#define SPHINCSPLUS_R3_192_SKPRF  24

// Note: the same sizes apply to SHAKE, HARAKA and "f" variants
#define SPHINCSPLUS_R3_256_CRYPTO_PUBLICKEYBYTES 64
#define SPHINCSPLUS_R3_256_CRYPTO_SECRETKEYBYTES 128
#define SPHINCSPLUS_R3_256_PKSEED 32
#define SPHINCSPLUS_R3_256_PKROOT 32
#define SPHINCSPLUS_R3_256_SKSEED 32
#define SPHINCSPLUS_R3_256_SKPRF  32

//     SPHINCSPPLUSPublicKey := SEQUENCE {
//       pkseed          OCTET STRING,     --n-byte public key seed
//       pkroot          OCTET STRING      --n-byte public hypertree root
//     }
#define SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_CRYPTO_PUBLICKEYBYTES) + \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_PKSEED) + SPHINCSPLUS_##NAME##_PKSEED + \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_PKROOT) + SPHINCSPLUS_##NAME##_PKROOT

/**
 * @brief 
 * subjectPublicKeyInfo := SEQUENCE {
 *  algorithm          AlgorithmIdentifier  -- see chapter above
 *  subjectPublicKey   BIT STRING           -- see chapter below
 * }
 */
#define SPHINCSPLUSXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(NAME, NAME2) \
  QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)) + SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

//     SPHINCSPLUSPrivateKey ::= SEQUENCE {
//       version         INTEGER {v2(1)}      --syntax version 2 (round 3)
//       skseed          OCTET STRING,        --n-byte private key seed
//       skprf           OCTET STRING,        --n-byte private key seed
//       PublicKey       SPHINCSPLUSPublicKey --public key
//     }
#define SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_SKSEED) + SPHINCSPLUS_##NAME##_SKSEED + \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_SKPRF) + SPHINCSPLUS_##NAME##_SKPRF + \
  SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)

#define SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME) \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_CRYPTO_SECRETKEYBYTES) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_SKSEED) + SPHINCSPLUS_##NAME##_SKSEED + \
  QSC_ASN_TLLEN(SPHINCSPLUS_##NAME##_SKPRF) + SPHINCSPLUS_##NAME##_SKPRF

/**
 * PrivateKeyInfo ::=  SEQUENCE {
 *   version               INTEGER             -- PKCS#8 syntax ver
 *   privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *   privateKey            OCTET STRING,       -- see chapter below
 *   attributes            [0]  IMPLICIT Attributes OPTIONAL
 * }
 */
#define SPHINCSPLUSXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(NAME, NAME2) \
  QSC_ASN_TLLEN(QSC_ASN_TLLEN(1) + 1 + QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID)) + QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID) + QSC_ASN_TLLEN(0) + QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)) + SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)

#define SPHINCSPLUSXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(NAME, NAME2) \
  QSC_ASN_TLLEN(QSC_ASN_TLLEN(1) + 1 + QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID)) + QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID) + QSC_ASN_TLLEN(0) + QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + \
  QSC_ASN_TLLEN(1) + 1 + \
  QSC_ASN_TLLEN(QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID)) + \
  QSC_ASN_OIDLEN(QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME2##_OID) + \
  QSC_ASN_TLLEN(0) + \
  QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)) + SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(NAME)

#define SPHINCSPLUSXXX_asntlp_pk_len 3

#define SPHINCSPLUS_ASNTLP_PK(NAME) \
  static const qsc_asntl_t SPHINCSPLUS_##NAME##_asntlp_pk[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asnenc_flag = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = SPHINCSPLUS_##NAME##_PKSEED, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = SPHINCSPLUS_##NAME##_PKROOT, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      } \
  };

SPHINCSPLUS_ASNTLP_PK(R3_128);
SPHINCSPLUS_ASNTLP_PK(R3_192);
SPHINCSPLUS_ASNTLP_PK(R3_256);

#define SPHINCSPLUSXXX_asntlp_sk_len 7

//     SPHINCSPLUSPrivateKey ::= SEQUENCE {
//       version         INTEGER {v2(1)}      --syntax version 2 (round 3)
//       skseed          OCTET STRING,        --n-byte private key seed
//       skprf           OCTET STRING,        --n-byte private key seed
//       PublicKey       SPHINCSPLUSPublicKey --public key
//     }
#define SPHINCSPLUS_ASNTLP_SK(NAME) \
  static const qsc_asntl_t SPHINCSPLUS_##NAME##_asntlp_sk[] = { \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME) - QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(NAME)), \
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
          .asnlen = SPHINCSPLUS_##NAME##_SKSEED, \
          .asnenc_flag = 1, \
          .asndec_flag = 1, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = SPHINCSPLUS_##NAME##_SKPRF, \
          .asnenc_flag = 1, \
          .asndec_flag = 1 \
      }, \
      { \
          .asntag = QSC_ASN1_SEQUENCE, \
          .asnlen = SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME) - QSC_ASN_TLLEN(SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(NAME)), \
          .asnenc_flag = 2, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = SPHINCSPLUS_##NAME##_PKSEED, \
          .asnenc_flag = 2, \
          .asndec_flag = 3, \
      }, \
      { \
          .asntag = QSC_ASN1_OCTETSTRING, \
          .asnlen = SPHINCSPLUS_##NAME##_PKROOT, \
          .asnenc_flag = 2, \
          .asndec_flag = 3, \
      } \
  };

SPHINCSPLUS_ASNTLP_SK(R3_128);
SPHINCSPLUS_ASNTLP_SK(R3_192);
SPHINCSPLUS_ASNTLP_SK(R3_256);

#define SPHINCSPLUS_VARIANT(BASE, NAME, FULLNAME) \
    static const qsc_encoding_impl_t Sphincsplus_##NAME##_encodings_arr[] = { \
            { \
                .encoding_name = "draft-uni-qsckeys-sphincsplus-00/p8-spki", \
                .algorithm_oid = QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME##_OID, \
                .crypto_publickeybytes = SPHINCSPLUSXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(BASE, NAME), \
                .crypto_secretkeybytes = SPHINCSPLUSXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES(BASE, NAME), \
                .crypto_publickeybytes_nooptional = SPHINCSPLUSXXX_CRYPTO_ASN1_SUBJECTPUBLICKEYINFOBYTES(BASE, NAME), \
                .crypto_secretkeybytes_nooptional = SPHINCSPLUSXXX_CRYPTO_ASN1_PRIVATEKEYINFOBYTES_NOOPTIONAL(BASE, NAME), \
                .crypto_bytes = 0, \
                .pk_asntl_len = SPHINCSPLUSXXX_asntlp_pk_len, \
                .pk_asntl = SPHINCSPLUS_##BASE##_asntlp_pk, \
                .sk_asntl_len = SPHINCSPLUSXXX_asntlp_sk_len, \
                .sk_asntl = SPHINCSPLUS_##BASE##_asntlp_sk, \
                .encode = qsc_encode_draft_uni_qsckeys_01, \
                .decode = qsc_decode_draft_uni_qsckeys_01, \
            }, \
            { \
                .encoding_name = "draft-uni-qsckeys-sphincsplus-00/sk-pk", \
                .algorithm_oid = QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME##_OID, \
                .crypto_publickeybytes = SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(BASE), \
                .crypto_secretkeybytes = SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES(BASE), \
                .crypto_publickeybytes_nooptional = SPHINCSPLUSXXX_CRYPTO_ASN1_PUBLICKEYBYTES(BASE), \
                .crypto_secretkeybytes_nooptional = SPHINCSPLUSXXX_CRYPTO_ASN1_SECRETKEYBYTES_NOOPTIONAL(BASE), \
                .pk_asntl_len = SPHINCSPLUSXXX_asntlp_pk_len, \
                .pk_asntl = SPHINCSPLUS_##BASE##_asntlp_pk, \
                .sk_asntl_len = SPHINCSPLUSXXX_asntlp_sk_len, \
                .sk_asntl = SPHINCSPLUS_##BASE##_asntlp_sk, \
                .encode = qsc_encode_draft_uni_qsckeys_01_skpk, \
                .decode = qsc_decode_draft_uni_qsckeys_01, \
            }, \
    }; \
    const qsc_encoding_t SPHINCSPLUS_##NAME##_encodings = { \
        .algorithm_name = FULLNAME, \
        .algorithm_oid_str = QSC_ALGORITHM_SIG_SPHINCSPLUS_##NAME##_OID_STR, \
        .encodings_len = 2, \
        .encoding = Sphincsplus_##NAME##_encodings_arr, \
        .raw_crypto_publickeybytes = SPHINCSPLUS_##BASE##_CRYPTO_PUBLICKEYBYTES, \
        .raw_crypto_secretkeybytes = SPHINCSPLUS_##BASE##_CRYPTO_SECRETKEYBYTES, \
        .raw_private_key_encodes_public_key = 1 \
    };

SPHINCSPLUS_VARIANT(R3_128, R3_SHA2_128F_ROBUST, "sphincs-sha256-128f-robust");
SPHINCSPLUS_VARIANT(R3_128, R3_SHA2_128F_SIMPLE, "sphincs-sha256-128f-simple");
SPHINCSPLUS_VARIANT(R3_128, R3_SHA2_128S_ROBUST, "sphincs-sha256-128s-robust");
SPHINCSPLUS_VARIANT(R3_128, R3_SHA2_128S_SIMPLE, "sphincs-sha256-128s-simple");
SPHINCSPLUS_VARIANT(R3_192, R3_SHA2_192F_ROBUST, "sphincs-sha256-192f-robust");
SPHINCSPLUS_VARIANT(R3_192, R3_SHA2_192F_SIMPLE, "sphincs-sha256-192f-simple");
SPHINCSPLUS_VARIANT(R3_192, R3_SHA2_192S_ROBUST, "sphincs-sha256-192s-robust");
SPHINCSPLUS_VARIANT(R3_192, R3_SHA2_192S_SIMPLE, "sphincs-sha256-192s-simple");
SPHINCSPLUS_VARIANT(R3_256, R3_SHA2_256F_ROBUST, "sphincs-sha256-256f-robust");
SPHINCSPLUS_VARIANT(R3_256, R3_SHA2_256F_SIMPLE, "sphincs-sha256-256f-simple");
SPHINCSPLUS_VARIANT(R3_256, R3_SHA2_256S_ROBUST, "sphincs-sha256-256s-robust");
SPHINCSPLUS_VARIANT(R3_256, R3_SHA2_256S_SIMPLE, "sphincs-sha256-256s-simple");

SPHINCSPLUS_VARIANT(R3_128, R3_SHAKE_128F_ROBUST, "sphincs-shake256-128f-robust");
SPHINCSPLUS_VARIANT(R3_128, R3_SHAKE_128F_SIMPLE, "sphincs-shake256-128f-simple");
SPHINCSPLUS_VARIANT(R3_128, R3_SHAKE_128S_ROBUST, "sphincs-shake256-128s-robust");
SPHINCSPLUS_VARIANT(R3_128, R3_SHAKE_128S_SIMPLE, "sphincs-shake256-128s-simple");
SPHINCSPLUS_VARIANT(R3_192, R3_SHAKE_192F_ROBUST, "sphincs-shake256-192f-robust");
SPHINCSPLUS_VARIANT(R3_192, R3_SHAKE_192F_SIMPLE, "sphincs-shake256-192f-simple");
SPHINCSPLUS_VARIANT(R3_192, R3_SHAKE_192S_ROBUST, "sphincs-shake256-192s-robust");
SPHINCSPLUS_VARIANT(R3_192, R3_SHAKE_192S_SIMPLE, "sphincs-shake256-192s-simple");
SPHINCSPLUS_VARIANT(R3_256, R3_SHAKE_256F_ROBUST, "sphincs-shake256-256f-robust");
SPHINCSPLUS_VARIANT(R3_256, R3_SHAKE_256F_SIMPLE, "sphincs-shake256-256f-simple");
SPHINCSPLUS_VARIANT(R3_256, R3_SHAKE_256S_ROBUST, "sphincs-shake256-256s-robust");
SPHINCSPLUS_VARIANT(R3_256, R3_SHAKE_256S_SIMPLE, "sphincs-shake256-256s-simple");

SPHINCSPLUS_VARIANT(R3_128, R3_HARAKA_128F_ROBUST, "sphincs-haraka-128f-robust");
SPHINCSPLUS_VARIANT(R3_128, R3_HARAKA_128F_SIMPLE, "sphincs-haraka-128f-simple");
SPHINCSPLUS_VARIANT(R3_128, R3_HARAKA_128S_ROBUST, "sphincs-haraka-128s-robust");
SPHINCSPLUS_VARIANT(R3_128, R3_HARAKA_128S_SIMPLE, "sphincs-haraka-128s-simple");
SPHINCSPLUS_VARIANT(R3_192, R3_HARAKA_192F_ROBUST, "sphincs-haraka-192f-robust");
SPHINCSPLUS_VARIANT(R3_192, R3_HARAKA_192F_SIMPLE, "sphincs-haraka-192f-simple");
SPHINCSPLUS_VARIANT(R3_192, R3_HARAKA_192S_ROBUST, "sphincs-haraka-192s-robust");
SPHINCSPLUS_VARIANT(R3_192, R3_HARAKA_192S_SIMPLE, "sphincs-haraka-192s-simple");
SPHINCSPLUS_VARIANT(R3_256, R3_HARAKA_256F_ROBUST, "sphincs-haraka-256f-robust");
SPHINCSPLUS_VARIANT(R3_256, R3_HARAKA_256F_SIMPLE, "sphincs-haraka-256f-simple");
SPHINCSPLUS_VARIANT(R3_256, R3_HARAKA_256S_ROBUST, "sphincs-haraka-256s-robust");
SPHINCSPLUS_VARIANT(R3_256, R3_HARAKA_256S_SIMPLE, "sphincs-haraka-256s-simple");
