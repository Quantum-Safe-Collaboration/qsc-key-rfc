// SPDX-License-Identifier: Apache-2.0 and Unknown
// Modified on Jul 18, 2022 to test serialization
/*
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
 
NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
 
You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <qsc_encoding.h>

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_VERIFICATION_ERROR -2
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

static void print_uchar(const unsigned char* d, int dlen, const char* title) {
    printf("%s: ", title);
    for (int i = 0; i < dlen; ++i)
        printf("%02X", d[i]);
    printf("\n");
}

static void print_hex(const char* title, const unsigned char* seq, size_t seqLen, int newline) {
  if (title)
    printf("%s: ", title);
  for (int i = 0; i < seqLen; ++i) {
    printf("%02X", seq[i]);
  }
  if (newline)
      printf("\n");
}

int
test_nist_kat(const qsc_encoding_t * params, const qsc_encoding_impl_t * encoding, int withoptional)
{
    char                fn_rsp[64];
    FILE                *fp_rsp;
    unsigned char       seed[48];
    unsigned char       *ct, *ss, *ss1;
    int                 count;
    int                 done;
    unsigned char       *pk, *sk, *pkEnc, *skEnc, *pkEncDec, *skEncDec;
    int                 ret_val;

    pk = calloc(params->raw_crypto_publickeybytes, 1);
    sk = calloc(params->raw_crypto_secretkeybytes, 1);

    if (withoptional) {
        pkEnc = calloc(encoding->crypto_publickeybytes, 1);
        skEnc = calloc(encoding->crypto_secretkeybytes, 1);
    } else {
        pkEnc = calloc(encoding->crypto_publickeybytes_nooptional, 1);
        skEnc = calloc(encoding->crypto_secretkeybytes_nooptional, 1);
    }

    pkEncDec = calloc(params->raw_crypto_publickeybytes, 1);
    skEncDec = calloc(params->raw_crypto_secretkeybytes, 1);

    const char* algname = params->algorithm_name;
    if (!algname) return KAT_DATA_ERROR;

    sprintf(fn_rsp, "../../KAT/%s/PQCsignKAT_%zu.rsp", algname, params->raw_crypto_secretkeybytes);
    if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
        sprintf(fn_rsp, "../../KAT/%s/PQCkemKAT_%zu.rsp", algname, params->raw_crypto_secretkeybytes);
        if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
            printf("Couldn't open <%s> for read\n", fn_rsp);
            return KAT_FILE_OPEN_ERROR;
        }
    }

    printf("# %s\n\n", algname);
    done = 0;
    do {
        if ( FindMarker(fp_rsp, "count = ") ) {
            if (fscanf(fp_rsp, "%d", &count) != 1) {
                done = 1;
                break;
            }
        } else {
            done = 1;
            break;
        }

        if ( !ReadHex(fp_rsp, pk, params->raw_crypto_publickeybytes, "pk = ") ) {
            printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        if ( !ReadHex(fp_rsp, sk, params->raw_crypto_secretkeybytes, "sk = ") ) {
            printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

        int ret = qsc_encode(params, encoding, pk, &pkEnc, sk, &skEnc, withoptional);
        if ( ret != QSC_ENC_OK ) {
            printf("ERROR: qsc_encode failed with code %d\n", ret);
            return KAT_DATA_ERROR;
        }

        ret = qsc_encode(params, encoding, pk, &pkEnc, 0, 0, withoptional);
        if ( ret != QSC_ENC_OK ) {
            printf("ERROR: qsc_encode failed with code %d\n", ret);
            return KAT_DATA_ERROR;
        }

        ret = qsc_encode(params, encoding, 0, 0, sk, &skEnc, withoptional);
        if (!params->raw_private_key_encodes_public_key && withoptional) {
            if (ret != QSC_ENC_ILLEGAL_INP) {
                printf("ERROR: qsc_encode should have failed with illegal input, but %d\n", ret);
                return KAT_DATA_ERROR;
            }
        } else {
            if (ret != QSC_ENC_OK ) {
                printf("ERROR: qsc_encode failed with code %d\n", ret);
                return KAT_DATA_ERROR;
            }
        }

        ret = qsc_encode(params, encoding, 0, &pkEnc, sk, &skEnc, withoptional);
        if (!params->raw_private_key_encodes_public_key) {
            if (ret != QSC_ENC_ILLEGAL_INP) {
                printf("ERROR: qsc_encode should have failed with illegal input, but %d\n", ret);
                return KAT_DATA_ERROR;
            }
        } else {
            if (ret != QSC_ENC_OK ) {
                printf("ERROR: qsc_encode failed with code %d\n", ret);
                return KAT_DATA_ERROR;
            }
        }

        ret = qsc_encode(params, encoding, 0, &pkEnc, sk, 0, withoptional);
        if (!params->raw_private_key_encodes_public_key) {
            if (ret != QSC_ENC_ILLEGAL_INP) {
                printf("ERROR: qsc_encode should have failed with illegal input, but %d\n", ret);
                return KAT_DATA_ERROR;
            }
        } else {
            if (ret != QSC_ENC_OK ) {
                printf("ERROR: qsc_encode failed with code %d\n", ret);
                return KAT_DATA_ERROR;
            }
        }

#if 0
        char strpk[80]; char strsk[80];
        int wbpk = sprintf(strpk, "%s-encoding-%d.pk.der", params->algorithm_oid_name, 0);
        int wbsk = sprintf(strsk, "%s-encoding-%d.sk.der", params->algorithm_oid_name, 0);
        FILE *write_ptr_pk;
        FILE *write_ptr_sk;
        write_ptr_pk = fopen(strpk,"wb");  // w for write, b for binary
        write_ptr_sk = fopen(strsk,"wb");  // w for write, b for binary
        fwrite(pkEnc,encoding->crypto_publickeybytes,1,write_ptr_pk); // write 10 bytes from our buffer
        fclose(write_ptr_pk);
        fwrite(skEnc,encoding->crypto_secretkeybytes,1,write_ptr_sk); // write 10 bytes from our buffer
        fclose(write_ptr_sk);
        return 0;
#endif



        ret = qsc_decode(params, encoding, pkEnc, &pkEncDec, 0, 0, withoptional); // should always work
        if ( ret != QSC_ENC_OK ) {
            printf("ERROR: qsc_decode failed with code %d\n", ret);
            return KAT_DATA_ERROR;
        }

        if (memcmp(pk, pkEncDec, params->raw_crypto_publickeybytes)) {
            printf("ERROR: encoding - public keys don't match\n");
            return KAT_DATA_ERROR;
        }

        ret = qsc_decode(params, encoding, pkEnc, 0, skEnc, &skEncDec, withoptional);
        if ( ret != QSC_ENC_OK ) {
            printf("ERROR: qsc_encode failed with code %d\n", ret);
            return KAT_DATA_ERROR;
        }

        if (memcmp(sk, skEncDec, params->raw_crypto_secretkeybytes)) {
            printf("ERROR: encoding - secret keys don't match\n");
            return KAT_DATA_ERROR;
        }

        ret = qsc_decode(params, encoding, 0, 0, skEnc, &skEncDec, withoptional);
        if (!withoptional && params->raw_private_key_encodes_public_key) {
            if (ret != QSC_ENC_ILLEGAL_INP) {
                printf("ERROR: qsc_encode should have failed with illegal input, but %d\n", ret);
                return KAT_DATA_ERROR;
            }
        } else {
            if (ret != QSC_ENC_OK ) {
                printf("ERROR: qsc_encode failed with code %d\n", ret);
                return KAT_DATA_ERROR;
            }
            if (memcmp(sk, skEncDec, params->raw_crypto_secretkeybytes)) {
                printf("ERROR: encoding - secret keys don't match\n");
                return KAT_DATA_ERROR;
            }
            if (memcmp(pk, pkEncDec, params->raw_crypto_publickeybytes)) {
                printf("ERROR: encoding - public keys don't match\n");
                return KAT_DATA_ERROR;
            }
        }

        ret = qsc_decode(params, encoding, 0, &pkEncDec, skEnc, &skEncDec, withoptional);
        if (!withoptional) {
            if (ret != QSC_ENC_ILLEGAL_INP) {
                printf("ERROR: qsc_encode should have failed with illegal input, but %d\n", ret);
                return KAT_DATA_ERROR;
            }
        } else {
            if (ret != QSC_ENC_OK ) {
                printf("ERROR: qsc_encode failed with code %d\n", ret);
                return KAT_DATA_ERROR;
            }
            if (memcmp(sk, skEncDec, params->raw_crypto_secretkeybytes)) {
                printf("ERROR: encoding - secret keys don't match\n");
                return KAT_DATA_ERROR;
            }
            if (memcmp(pk, pkEncDec, params->raw_crypto_publickeybytes)) {
                printf("ERROR: encoding - public keys don't match\n");
                return KAT_DATA_ERROR;
            }
        }

        ret = qsc_decode(params, encoding, 0, &pkEncDec, skEnc, 0, withoptional);
        if (!withoptional) {
            if (ret != QSC_ENC_ILLEGAL_INP) {
                printf("ERROR: qsc_encode should have failed with illegal input, but %d\n", ret);
                return KAT_DATA_ERROR;
            }
        } else {
            if (ret != QSC_ENC_OK ) {
                printf("ERROR: qsc_encode failed with code %d\n", ret);
                return KAT_DATA_ERROR;
            }
            if (memcmp(pk, pkEncDec, params->raw_crypto_publickeybytes)) {
                printf("ERROR: encoding - public keys don't match\n");
                return KAT_DATA_ERROR;
            }
        }

        ret = qsc_decode(params, encoding, pkEnc, &pkEncDec, skEnc, &skEncDec, withoptional);
        if ( ret != QSC_ENC_OK ) {
            printf("ERROR: qsc_encode failed with code %d\n", ret);
            return KAT_DATA_ERROR;
        }

        if (memcmp(pk, pkEncDec, params->raw_crypto_publickeybytes)) {
            printf("ERROR: encoding - public keys don't match\n");
            return KAT_DATA_ERROR;
        }

        if (memcmp(sk, skEncDec, params->raw_crypto_secretkeybytes)) {
            print_hex("sk      ", sk, params->raw_crypto_secretkeybytes, 1);
            print_hex("skEnc   ", skEnc, encoding->crypto_secretkeybytes_nooptional, 1);
            print_hex("skEncDec", skEncDec, params->raw_crypto_secretkeybytes, 1);
            printf("ERROR: encoding - secret keys don't match\n");
            return KAT_DATA_ERROR;
        }


    } while ( !done );

    fclose(fp_rsp);
    printf("Known Answer Tests PASSED. \n");
    printf("\n\n");

    free(pk);
    free(sk);
    free(pkEnc);
    free(skEnc);
    free(pkEncDec);
    free(skEncDec);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//

int
FindMarker(FILE *infile, const char *marker)
{
    char	line[MAX_MARKER_LEN];
    int		i, len;
    int curr_line;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
    {
        curr_line = fgetc(infile);
        line[i] = curr_line;
        if (curr_line == EOF )
            return 0;
    }
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        curr_line = fgetc(infile);
        line[len-1] = curr_line;
        if (curr_line == EOF )
            return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
    int			i, ch, started;
    unsigned char	ich;

    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if ( FindMarker(infile, str) )
        while ( (ch = fgetc(infile)) != EOF ) {
            if ( !isxdigit(ch) ) {
                if ( !started ) {
                    if ( ch == '\n' )
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ( (ch >= '0') && (ch <= '9') )
                ich = ch - '0';
            else if ( (ch >= 'A') && (ch <= 'F') )
                ich = ch - 'A' + 10;
            else if ( (ch >= 'a') && (ch <= 'f') )
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
            ich = 0;

            for ( i=0; i<Length-1; i++ )
                A[i] = (A[i] << 4) | (A[i+1] >> 4);
            A[Length-1] = (A[Length-1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long  i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
