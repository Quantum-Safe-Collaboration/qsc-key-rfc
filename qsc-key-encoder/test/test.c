// SPDX-License-Identifier: Apache-2.0 and MIT
#include <qsc_encoding.h>
#include <stdio.h>

// Test NIST KAT -(encode)-> Encoding -(decode)-> NIST KAT
int
test_nist_kat(const qsc_encoding_t * params, const qsc_encoding_impl_t * encoding, int withoptional);

int main(int argc, char *argv[]) {
    const qsc_encoding_t* ctx = 0;
    const qsc_encoding_impl_t* ctx_impl = 0;

    if (argc < 3) {
        printf("Usage: qsc_key_encoder_test <algorithm> <encoding>\n");
        return 1;
    }

    if (qsc_encoding_by_name_oid(&ctx, &ctx_impl, argv[1], argv[2]) != QSC_ENC_OK) {
        printf("Not a valid algorithm or encoding: %s - %s\n", argv[1], argv[2]);
        return QSC_ENC_ERR;
    }
    
    int rc = test_nist_kat(ctx, ctx_impl, 1);
    rc |= test_nist_kat(ctx, ctx_impl, 0);

    return rc;
}
