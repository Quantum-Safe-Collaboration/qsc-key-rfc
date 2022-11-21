// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <string.h>
#include <qsc_encoding.h>


static size_t qsc_asn_something(unsigned char *wire, size_t wbytes,
                                              size_t seq_net_bytes,
                                              unsigned char tag)
{
	if (seq_net_bytes < 0x80) {                   // [tag] ...len... 00
		if (wire && (wbytes >= 2)) {
			*(wire - 2) = tag;
			*(wire - 1) = (unsigned char) seq_net_bytes;
		}
		return 2;
	} else if (seq_net_bytes < 0x10000) {         // assume  [tag] 82 xx yy
		if (wire && (wbytes >= 4)) {
			*(wire - 4) = tag;
			*(wire - 3) = 0x82;
			*(wire - 2) =
				(unsigned char) (seq_net_bytes >> 8);
			*(wire - 1) =
				(unsigned char)  seq_net_bytes;
		}
		return 4;
	} else if (seq_net_bytes < 0x1000000) {      // assume  [tag] 83 xx yy zz
        if (wire && (wbytes >= 5)) {
			*(wire - 5) = tag;
			*(wire - 4) = 0x83;
			*(wire - 3) =
				(unsigned char) (seq_net_bytes >> 16);
			*(wire - 2) =
				(unsigned char) (seq_net_bytes >> 8);
            *(wire - 1) =
                (unsigned char) seq_net_bytes;
		}
		return 5;
    }
    return 0;
}

static int qsc_asn_something_validate(unsigned char *wire, size_t wbytes,
                                                    size_t seq_net_bytes,
                                              unsigned char tag)
{
    int res = -1;
    int size = 0;

	if (seq_net_bytes < 0x80) {                   // [tag] ...len... 00
		if (wire && (wbytes >= 2)) {
			res &= 0 - (*(wire - 2) == tag);
			res &= 0 - (*(wire - 1) == (unsigned char) seq_net_bytes);
		}
        size = 2;
	} else if (seq_net_bytes < 0x10000) {         // assume  [tag] 82 xx yy
		if (wire && (wbytes >= 4)) {
			res &= 0 - (*(wire - 4) == tag);
			res &= 0 - (*(wire - 3) == 0x82);
			res &= 0 - (*(wire - 2) ==
				(unsigned char) (seq_net_bytes >> 8));
			res &= 0 - (*(wire - 1) ==
				(unsigned char)  seq_net_bytes);
		}
        size = 4;
	} else if (seq_net_bytes < 0x1000000) {       // assume  [tag] 83 xx yy zz
		if (wire && (wbytes >= 5)) {
			res &= 0 - (*(wire - 5) == tag);
			res &= 0 - (*(wire - 4) == 0x83);
			res &= 0 - (*(wire - 3) ==
				(unsigned char) (seq_net_bytes >> 16));
			res &= 0 - (*(wire - 2) ==
				(unsigned char)  (seq_net_bytes >> 8));
            res &= 0 - (*(wire - 1) ==
				(unsigned char)  seq_net_bytes);
		}
        size = 4;
	}
    return res & size;
}

size_t qsc_asn_bitstr(unsigned char *wire, size_t wbytes,
                                                  size_t bstring_net_bytes)
{
    return qsc_asn_something(wire, wbytes, bstring_net_bytes, 
                             QSC_ASN1_BITSTRING);
}

size_t qsc_asn_sequence(unsigned char *wire, size_t wbytes,
                                      size_t seq_net_bytes)
{
	return qsc_asn_something(wire, wbytes, seq_net_bytes,
	                         QSC_ASN1_SEQUENCE);
}

size_t qsc_asn_octetstr(unsigned char *wire, size_t wbytes,
                                      size_t seq_net_bytes)
{
	return qsc_asn_something(wire, wbytes, seq_net_bytes,
	                         QSC_ASN1_OCTETSTRING);
}

size_t qsc_asn_int(unsigned char *wire, size_t wbytes,
                          unsigned char i)
{
	if (wire && (wbytes >= 3)) {
		*(wire - 3) = QSC_ASN1_INT;
		*(wire - 2) = 1;
		*(wire - 1) = i;
	}

	return 3;
}

static size_t qsc_asn_null(unsigned char *wire, size_t wbytes)
{
	if (wire && (wbytes >= 2)) {
		*(wire - 2) = QSC_ASN1_NULL;
		*(wire - 1) = 0x00;
	}

	return 2;
}


static size_t qsc_gn_oid2wire(unsigned char *wire, size_t wbytes,
                              const char* arcs, size_t arcslen)
{
	size_t wr;

	wr = arcslen;

	if (wire && (wr > wbytes))
		return 0;              // insufficient output

	if (wire) {
		wire -= wr;
		for (int i = 0; i < arcslen; ++i)
			*wire++ = (unsigned char) arcs[i];
	}

	return wr;
}


static int validate_decode_asntl(const qsc_asntl_t* asntlstr, int asntllen, size_t obytes, const unsigned char* k, const unsigned char* k2, unsigned char* kdec, unsigned char asnenc_mask, unsigned char asndec_mask) {
    int wr = 0;
    unsigned char* kout = kdec;
    const unsigned char* kin = k, *k2in = k2;
    const unsigned char **xin = NULL;

    int koutbytes = (int) obytes;

    for (int i = asntllen - 1; i >= 0; --i) {
        xin = NULL;

        int asnlen = asntlstr[i].asnlen;
        int asntag = asntlstr[i].asntag;
        int asnval = asntlstr[i].asnvalue;
        int asnenc_flag = asntlstr[i].asnenc_flag;
        int asndec_flag = asntlstr[i].asndec_flag;

        int encpub = asntlstr[i].encpub;

        int asnenc = asnenc_mask & asnenc_flag; // element was encoded
        int asndec = asndec_mask & asndec_flag; // element is to be decoded

        if (!asnenc && !asndec) // wasn't encoded, doesn't need to be decoded -> skip
            continue;
        else if (asnenc && !asndec) { // was encoded but doesn't need to be decoded -> move the pointer in the input
            if (asntag != QSC_ASN1_SEQUENCE) 
                kin -= asnlen;
            int asntaglen = qsc_asn_something_validate(0, koutbytes, asnlen, asntag);
            if (asntaglen <= 0) return QSC_ENC_ERR;
            kin -= asntaglen;
            xin = NULL;
        } else if (asnenc && asndec) { // was encoded and needs to be decoded
            xin = &kin;
        } else if (!asnenc && asndec) { // was not encode but needs to be decoded from k2
            xin = &k2in;   
        } else { // Not possible
            return QSC_ENC_ERR;
        }

        if (xin) { // something needs to be decoded
            if (asntag != QSC_ASN1_SEQUENCE) {
                kout -= asnlen;
                koutbytes -= asnlen;
                wr += asnlen;
                *xin -= asnlen;
            }

            int asntaglen = qsc_asn_something_validate(0, koutbytes, asnlen, asntag);
            if (asntaglen <= 0) return QSC_ENC_ERR;
            *xin -= asntaglen;
        }
    }

    return koutbytes >= 0;
}

static int decode_asntl(const qsc_asntl_t* asntlstr, int asntllen, size_t obytes, const unsigned char* k, const unsigned char* k2, unsigned char* kdec, unsigned char asnenc_mask, unsigned char asndec_mask) {
    int wr = 0;
    unsigned char* kout = kdec;
    const unsigned char* kin = k, *k2in = k2;
    const unsigned char **xin = NULL;

    if (!validate_decode_asntl(asntlstr, asntllen, obytes, k, k2, kdec, asnenc_mask, asndec_mask)) {
        return QSC_ENC_ERR;
    }

    size_t koutbytes = obytes;

    for (int i = asntllen - 1; i >= 0; --i) {
        xin = NULL;

        int asnlen = asntlstr[i].asnlen;
        int asntag = asntlstr[i].asntag;
        int asnval = asntlstr[i].asnvalue;
        int asnenc_flag = asntlstr[i].asnenc_flag;
        int asndec_flag = asntlstr[i].asndec_flag;

        int encpub = asntlstr[i].encpub;

        int asnenc = asnenc_mask & asnenc_flag; // element was encoded
        int asndec = asndec_mask & asndec_flag; // element is to be decoded

        if (!asnenc && !asndec) // wasn't encoded, doesn't need to be decoded -> skip
            continue;
        else if (asnenc && !asndec) { // was encoded but doesn't need to be decoded -> move the pointer in the input
            if (asntag != QSC_ASN1_SEQUENCE) 
                kin -= asnlen;
            int asntaglen = qsc_asn_something(0, koutbytes, asnlen, asntag);
            if (asntaglen <= 0) return QSC_ENC_ERR;
            kin -= asntaglen;
            xin = NULL;
        } else if (asnenc && asndec) { // was encoded and needs to be decoded
            xin = &kin;
        } else if (!asnenc && asndec) { // was not encode but needs to be decoded from k2
            xin = &k2in;   
        } else { // Not possible
            return QSC_ENC_ERR;
        }

        if (xin) { // something needs to be decoded
            if (asntag != QSC_ASN1_SEQUENCE) {
                if (asntag == QSC_ASN1_INT)
                    *(kout - asnlen) = *(*xin - asnlen);
                else
                    memmove(kout - asnlen, *xin - asnlen, asnlen);
                kout -= asnlen;
                koutbytes -= asnlen;
                wr += asnlen;
                *xin -= asnlen;
            }

            int asntaglen = qsc_asn_something(0, koutbytes, asnlen, asntag);
            if (asntaglen <= 0) return QSC_ENC_ERR;
            *xin -= asntaglen;
        }
    }

    return wr;
}

static int encode_asntl(const qsc_asntl_t* asntlstr, int asntllen, size_t obytes, const unsigned char* k, const unsigned char* k2, unsigned char* kenc, int asnenc_mask) {
    int wr = 0;
    unsigned char* kout = kenc;
    const unsigned char* kin = k, *k2in = k2;
    size_t koutbytes = obytes;

    for (int i = asntllen - 1; i >= 0; --i) {
        int asnlen = asntlstr[i].asnlen;
        int asntag = asntlstr[i].asntag;
        int asnval = asntlstr[i].asnvalue;
        int asnpub = asntlstr[i].encpub; // This means: element is not in raw input and MUST come from k2 input.
        int asnenc_flag = asntlstr[i].asnenc_flag; // 0 means, never encoded, !0 means -> encoding depends on asnenc_mask.

        if (!(asnenc_mask & asnenc_flag)) { // Don't encode
            if (!asnpub && asnenc_flag != 0 && asntag != QSC_ASN1_SEQUENCE) // -> element IS in raw input and is SOMETIMES encoded
                kin -= asnlen;
        } else { // encode
            if (asntag == QSC_ASN1_INT) { // special treatment for INT since value is fixed
                *(kout - asnlen) = asnval;
                kout -= asnlen;
                koutbytes -= asnlen;
                wr += asnlen;
            } else if (asntag != QSC_ASN1_SEQUENCE) {
                if (asnpub) { // MUST be taken from k2
                    memmove(kout - asnlen, k2in - asnlen, asnlen);
                    k2in -= asnlen;
                } else {
                    memmove(kout - asnlen, kin - asnlen, asnlen);
                    kin -= asnlen;
                }
                kout -= asnlen;
                koutbytes -= asnlen;
                wr += asnlen;
            }
            int asntaglen = qsc_asn_something(kout, koutbytes, asnlen, asntag);
            if (asntaglen <= 0) return QSC_ENC_ERR;

            kout -= asntaglen;
            koutbytes -= asntaglen;
            wr += asntaglen;
        }
    }

    return wr;
}

/**
 * 
 * The encoding for public keys.
 * 
 * subjectPublicKeyInfo := SEQUENCE {
 *     algorithm          AlgorithmIdentifier  -- see chapter above
 *     subjectPublicKey   BIT STRING           -- see chapter below
 * }
 * 
 * Expects that subjectPublicKey is already written after wire.
 * 
 * @param ctx 
 * @param wire 
 * @param wbytes 
 * @return size_t 
 */
static size_t encode_SubjectPublicKeyInfo_part(const qsc_encoding_impl_t* ctx, unsigned char* wire, size_t wbytes, size_t spkbytes) {
	size_t seqBytes, algBytes, algtlbytes, spkbitBytes, algnullBytes, algseqBytes;
	size_t wr;

	spkbitBytes = qsc_asn_something(wire, wbytes, spkbytes, QSC_ASN1_BITSTRING);
	if (spkbitBytes <= 0) return QSC_ENC_ERR;

	wr = spkbitBytes;
	wire -= spkbitBytes;
	wbytes -= spkbitBytes;

    algnullBytes = qsc_asn_null(wire, wbytes);
    if (algnullBytes <= 0) return QSC_ENC_ERR;

    wr += algnullBytes;
    wire -= algnullBytes;
    wbytes -= algnullBytes;

	algBytes = qsc_gn_oid2wire(wire, wbytes, ctx->algorithm_oid, strlen(ctx->algorithm_oid));
	if (algBytes <= 0) return QSC_ENC_ERR;

	wr += algBytes;
	wire -= algBytes;
	wbytes -= algBytes;

    algseqBytes = qsc_asn_sequence(wire, wbytes, algnullBytes + algBytes);
    if (algseqBytes <= 0) return QSC_ENC_ERR;

    wr += algseqBytes;
    wire -= algseqBytes;
    wbytes -= algseqBytes;

	seqBytes = qsc_asn_sequence(wire, wbytes, spkbytes + wr);
	if (seqBytes <= 0) return QSC_ENC_ERR;

	wr += seqBytes;
	wire -= seqBytes;
	wbytes -= seqBytes;

	return wr;
}


static int encode_spki_PublicKey(const qsc_encoding_impl_t* ctx_out, unsigned char* sk, unsigned char* pk, unsigned char* pkenc, int withoptional) {
    int wr = 0;
    unsigned char* pkout = pkenc, *pkin = pk, *skin = sk;
    size_t expextedoutbytes = (withoptional ? ctx_out->crypto_publickeybytes : ctx_out->crypto_publickeybytes_nooptional);
    size_t pkoutbytes = expextedoutbytes;

    const qsc_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;

    const qsc_asntl_t* asntlstr_sk = ctx_out->sk_asntl;
    int asntllen_sk = ctx_out->sk_asntl_len;

    // Two cases: use pk or use sk
    int espki = 0;
    if (pk) // If pk is provided, take pk
        espki = encode_asntl(asntlstr_pk, asntllen_pk, pkoutbytes, pkin, 0, pkout, 1);
    else if (sk) // take sk, only encode the pk part (mask 2)
        espki = encode_asntl(asntlstr_sk, asntllen_sk, pkoutbytes, skin, 0, pkout, 2);
    else
        return QSC_ENC_ERR;
        
    if (espki <= 0) return QSC_ENC_ERR;

    pkout -= espki;
    pkoutbytes -= espki;
    wr += espki;

    if (wr != expextedoutbytes) return QSC_ENC_ERR;
    else return wr;
}

static int encode_SubjectPublicKeyInfo(const qsc_encoding_impl_t* ctx_out, const unsigned char* sk, const unsigned char* pk, unsigned char* pkenc, int withoptional) {
    int wr = 0;
    unsigned char* pkout = pkenc;
    const unsigned char* pkin = pk, *skin = sk;
    size_t expextedoutbytes = (withoptional ? ctx_out->crypto_publickeybytes : ctx_out->crypto_publickeybytes_nooptional);
    size_t pkoutbytes = expextedoutbytes;

    const qsc_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;

    const qsc_asntl_t* asntlstr_sk = ctx_out->sk_asntl;
    int asntllen_sk = ctx_out->sk_asntl_len;

    // Two cases: use pk or use sk
    int espki = 0;
    if (pk) // If pk is provided, take pk
        espki = encode_asntl(asntlstr_pk, asntllen_pk, pkoutbytes, pkin, 0, pkout, 1);
    else if (sk) // take sk, only encode the pk part (mask 2)
        espki = encode_asntl(asntlstr_sk, asntllen_sk, pkoutbytes, skin, 0, pkout, 2);
    else
        return QSC_ENC_ERR;
        
    if (espki <= 0) return QSC_ENC_ERR;

    pkout -= espki;
    pkoutbytes -= espki;
    wr += espki;

    int qsckey00bytesPK = encode_SubjectPublicKeyInfo_part(ctx_out, pkout, pkoutbytes, espki);
    if (qsckey00bytesPK <= 0) return QSC_ENC_ERR;

    pkout -= qsckey00bytesPK;
    pkoutbytes -= qsckey00bytesPK;
    wr += qsckey00bytesPK;

    if (wr != expextedoutbytes) return QSC_ENC_ERR;
    else return wr;
}

/**
 * @brief 
 * 
 * The encoding for private keys.
 * 
 *  PrivateKeyInfo ::=  SEQUENCE {
 *      version               INTEGER             -- PKCS#8 syntax ver
 *      privateKeyAlgorithm   AlgorithmIdentifier -- see chapter above
 *      privateKey            OCTET STRING,       -- see chapter below
 *      attributes            [0]  IMPLICIT Attributes OPTIONAL
 *  }
 * 
 * Expects that privateKey is already written after wire.
 * 
 * @param ctx 
 * @param wire 
 * @param wbytes 
 * @return size_t 
 */
static size_t encode_PrivateKeyInfo_part(const qsc_encoding_impl_t* ctx, unsigned char* wire, size_t wbytes, size_t pkbytes) {
	size_t seqBytes, algBytes, algtlBytes, pkbitBytes, versionBytes, algseqBytes, algnullBytes;
	size_t wr;

	pkbitBytes = qsc_asn_something(wire, wbytes, pkbytes, QSC_ASN1_OCTETSTRING);
	if (pkbitBytes <= 0) return QSC_ENC_ERR;

	wr = pkbitBytes;
	wire -= pkbitBytes;
	wbytes -= pkbitBytes;

    algnullBytes = qsc_asn_null(wire, wbytes);
    if (algnullBytes <= 0) return QSC_ENC_ERR;

    wr += algnullBytes;
    wire -= algnullBytes;
    wbytes -= algnullBytes;

	algBytes = qsc_gn_oid2wire(wire, wbytes, ctx->algorithm_oid, strlen(ctx->algorithm_oid));
	if (algBytes <= 0) return QSC_ENC_ERR;

	wr += algBytes;
	wire -= algBytes;
	wbytes -= algBytes;

    algseqBytes = qsc_asn_sequence(wire, wbytes, algnullBytes + algBytes);
    if (algseqBytes <= 0) return QSC_ENC_ERR;

    wr += algseqBytes;
    wire -= algseqBytes;
    wbytes -= algseqBytes;

	// Version = 0 (PKCS8)
	*(wire - 1) = 0;
	wr += 1;
	wire -= 1;
	wbytes -= 1;

	versionBytes = qsc_asn_something(wire, wbytes, 1, QSC_ASN1_INT);
	if (versionBytes <= 0) return QSC_ENC_ERR;

	wr += versionBytes;
	wire -= versionBytes;
	wbytes -= versionBytes;

	seqBytes = qsc_asn_sequence(wire, wbytes, pkbytes + wr);
	if (seqBytes <= 0) return QSC_ENC_ERR;

	wr += seqBytes;
	wire -= seqBytes;
	wbytes -= seqBytes;

	return wr;
}

static int encode_PrivateKeyInfo(const qsc_encoding_impl_t* ctx_out, const unsigned char* sk, const unsigned char* pk, unsigned char* skenc, int withoptional) {
    int wr = 0;
    unsigned char* skout = skenc;
    const unsigned char* pkin = pk, *skin = sk;
    size_t expextedoutbytes = (withoptional ? ctx_out->crypto_secretkeybytes : ctx_out->crypto_secretkeybytes_nooptional);
    size_t skoutbytes = expextedoutbytes;

    const qsc_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    const qsc_asntl_t* asntlstr_sk = ctx_out->sk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;
    int asntllen_sk = ctx_out->sk_asntl_len;

    int asnenc_mask = (withoptional ? 3 : 1);

    int skpart = encode_asntl(asntlstr_sk, asntllen_sk, skoutbytes, skin, pkin, skout, asnenc_mask);
    if (skpart <= 0) return QSC_ENC_ERR;

    skout -= skpart;
    skoutbytes -= skpart;
    wr += skpart;

    int qsckey00bytesSK = encode_PrivateKeyInfo_part(ctx_out, skout, skoutbytes, wr);
    if (qsckey00bytesSK <= 0) return QSC_ENC_ERR;

    skout -= qsckey00bytesSK;
    skoutbytes -= qsckey00bytesSK;
    wr += qsckey00bytesSK;

    if (wr != expextedoutbytes) return QSC_ENC_ERR;
    else return wr;
}

static int encode_p8_PrivateKey(const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_out, unsigned char* sk, unsigned char* pk, unsigned char* skenc, int withoptional) {
    int wr = 0;
    unsigned char* skout = skenc, *pkin = pk, *skin = sk;

    size_t expextedoutbytes = (withoptional ? ctx_out->crypto_secretkeybytes : ctx_out->crypto_secretkeybytes_nooptional);
    size_t skoutbytes = expextedoutbytes;

    const qsc_asntl_t* asntlstr_pk = ctx_out->pk_asntl;
    const qsc_asntl_t* asntlstr_sk = ctx_out->sk_asntl;
    int asntllen_pk = ctx_out->pk_asntl_len;
    int asntllen_sk = ctx_out->sk_asntl_len;

    int asnenc_mask = (withoptional ? 3 : 1);

    int skpart = encode_asntl(asntlstr_sk, asntllen_sk, skoutbytes, skin, pkin, skout, asnenc_mask);
    if (skpart <= 0) return QSC_ENC_ERR;

    skout -= skpart;
    skoutbytes -= skpart;
    wr += skpart;

    if (wr != expextedoutbytes) return QSC_ENC_ERR;
    else return wr;
}

static int decode_SubjectPublicKeyInfo(const qsc_encoding_t* ctx_out, const qsc_encoding_impl_t* ctx_in, const unsigned char* sk, const unsigned char* pk, unsigned char* pkdec, int withoptional) {
    int wr = 0;
    unsigned char* pkout = pkdec;
    const unsigned char* pkin = pk, *skin = sk;
    size_t pkoutbytes = ctx_out->raw_crypto_publickeybytes;

    const qsc_asntl_t* asntlstr_pk = ctx_in->pk_asntl;
    int asntllen_pk = ctx_in->pk_asntl_len;

    const qsc_asntl_t* asntlstr_sk = ctx_in->sk_asntl;
    int asntllen_sk = ctx_in->sk_asntl_len;

    int asnenc_mask = (withoptional ? 3 : 1);

    int espki = 0;
    if (pk)
        espki = decode_asntl(asntlstr_pk, asntllen_pk, pkoutbytes, pkin, 0, pkout, asnenc_mask, 1);
    else if (sk)
        espki = decode_asntl(asntlstr_sk, asntllen_sk, pkoutbytes, skin, 0, pkout, asnenc_mask, 2);
    else
        return QSC_ENC_ERR;

    if (espki <= 0) return QSC_ENC_ERR;

    pkout -= espki;
    pkoutbytes -= espki;
    wr += espki;

    if (wr != ctx_out->raw_crypto_publickeybytes - ctx_out->raw_crypto_publickey_header_bytes) return QSC_ENC_ERR;
    else return wr;
}

static int decode_PrivateKeyInfo(const qsc_encoding_t* ctx_out, const qsc_encoding_impl_t* ctx_in, const unsigned char* sk, const unsigned char* pk, unsigned char* pkdec, unsigned char* skdec, int withoptional) {
    int wr = 0;
    unsigned char* skout = skdec, *pkout = pkdec;
    const unsigned char* skin = sk, *pkin = pk;
    size_t skoutbytes = ctx_out->raw_crypto_secretkeybytes;
    size_t pkoutbytes = ctx_out->raw_crypto_publickeybytes;

    const qsc_asntl_t* asntlstr_pk = ctx_in->pk_asntl;
    const qsc_asntl_t* asntlstr_sk = ctx_in->sk_asntl;
    int asntllen_pk = ctx_in->pk_asntl_len;
    int asntllen_sk = ctx_in->sk_asntl_len;

    int asnenc_mask = (withoptional ? 3 : 1); // was encrypted withoptional part or not
    int asndec_mask = (ctx_out->raw_private_key_encodes_public_key ? 3 : 1); // if pk in raw private key -> need to decode

    int skpart = decode_asntl(asntlstr_sk, asntllen_sk, skoutbytes, skin, pkin, skout, asnenc_mask, asndec_mask);
    if (skpart <= 0) return QSC_ENC_ERR;

    if (skpart != ctx_out->raw_crypto_secretkeybytes - ctx_out->raw_crypto_secretkey_header_bytes) return QSC_ENC_ERR;
    return skpart;
}

QSC_RC qsc_encode_draft_uni_qsckeys_01_skpk(const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_out, unsigned char* pk, unsigned char** pkenc, unsigned char* sk, unsigned char** skenc, int withoptional) {
    size_t wrpk = 0, wrsk = 0;
    unsigned char* pkout, *pkin;
    unsigned char* skout, *skin;
    size_t crypto_publickeybytes = (withoptional ? ctx_out->crypto_publickeybytes : ctx_out->crypto_publickeybytes_nooptional);
    size_t crypto_secretkeybytes = (withoptional ? ctx_out->crypto_secretkeybytes : ctx_out->crypto_secretkeybytes_nooptional);
    size_t pkoutbytes = crypto_publickeybytes;
    size_t skoutbytes = crypto_secretkeybytes;

    if (pkenc) {
        pkin = NULL;
        skin = NULL;
        pkout = (*pkenc) + crypto_publickeybytes;

        if (pk)
            pkin = pk + ctx->raw_crypto_publickeybytes;
        if (sk)
            skin = sk + ctx->raw_crypto_secretkeybytes;

        int encsikepk = encode_spki_PublicKey(ctx_out, skin, pkin, pkout, withoptional);
        if (encsikepk <= 0) return QSC_ENC_ERR;

        pkout -= encsikepk;
        pkoutbytes -= encsikepk;
        wrpk += encsikepk;

        if (wrpk != crypto_publickeybytes)
            return QSC_ENC_ERR;
    }

    if (skenc) {
        pkin = NULL;
        skin = NULL;
        skout = (*skenc) + crypto_secretkeybytes;

        if (sk)
            skin = sk + ctx->raw_crypto_secretkeybytes;
        if (pk)
            pkin = pk + ctx->raw_crypto_publickeybytes;

        int encprik = encode_p8_PrivateKey(ctx, ctx_out, skin, pkin, skout, withoptional);
        if (encprik <= 0) return QSC_ENC_ERR;
        skout -= encprik;
        skoutbytes -= encprik;
        wrsk += encprik;

        if (wrsk != crypto_secretkeybytes)
            return QSC_ENC_ERR;
        
    }
    return QSC_ENC_OK;
}

QSC_RC qsc_encode_draft_uni_qsckeys_01(const qsc_encoding_t* ctx, const qsc_encoding_impl_t* ctx_out, const unsigned char* pk, unsigned char** pkenc, const unsigned char* sk, unsigned char** skenc, int withoptional) {
    size_t wrpk = 0, wrsk = 0;
    unsigned char* pkout;
    const unsigned char* pkin;
    unsigned char* skout;
    const unsigned char* skin;
    size_t crypto_publickeybytes = (withoptional ? ctx_out->crypto_publickeybytes : ctx_out->crypto_publickeybytes_nooptional);
    size_t crypto_secretkeybytes = (withoptional ? ctx_out->crypto_secretkeybytes : ctx_out->crypto_secretkeybytes_nooptional);
    size_t pkoutbytes = crypto_publickeybytes;
    size_t skoutbytes = crypto_secretkeybytes;

    if (pkenc) {
        pkin = NULL;
        skin = NULL;
        pkout = (*pkenc) + crypto_publickeybytes;

        if (pk)
            pkin = pk + ctx->raw_crypto_publickeybytes;
        if (sk)
            skin = sk + ctx->raw_crypto_secretkeybytes;

        int encsikepk = encode_SubjectPublicKeyInfo(ctx_out, skin, pkin, pkout, withoptional);
        if (encsikepk <= 0) return QSC_ENC_ERR;

        pkout -= encsikepk;
        pkoutbytes -= encsikepk;
        wrpk += encsikepk;

        if (wrpk != crypto_publickeybytes)
            return QSC_ENC_ERR;
    }

    if (skenc) {
        pkin = NULL;
        skin = NULL;
        skout = (*skenc) + crypto_secretkeybytes;

        if (sk)
            skin = sk + ctx->raw_crypto_secretkeybytes;
        if (pk)
            pkin = pk + ctx->raw_crypto_publickeybytes;

        int encprik = encode_PrivateKeyInfo(ctx_out, skin, pkin, skout, withoptional);
        if (encprik <= 0) return QSC_ENC_ERR;
        skout -= encprik;
        skoutbytes -= encprik;
        wrsk += encprik;

        if (wrsk != crypto_secretkeybytes)
            return QSC_ENC_ERR;
    }
    return QSC_ENC_OK;
}

QSC_RC qsc_decode_draft_uni_qsckeys_01(const qsc_encoding_t* ctx, const qsc_encoding_impl_t* encoding, const unsigned char* pk, unsigned char** pkdec, const unsigned char* sk, unsigned char** skdec, int withoptional) {

    size_t wrpk = 0, wrsk = 0;

    const unsigned char *pkin = 0;
    const unsigned char *skin = 0;

    unsigned char *pkout = 0;
    unsigned char *skout = 0;

    size_t pkoutbytes = ctx->raw_crypto_publickeybytes;
    size_t skoutbytes = ctx->raw_crypto_secretkeybytes;

    size_t crypto_publickeybytes = (withoptional ? encoding->crypto_publickeybytes : encoding->crypto_publickeybytes_nooptional);
    size_t crypto_secretkeybytes = (withoptional ? encoding->crypto_secretkeybytes : encoding->crypto_secretkeybytes_nooptional);

    if (pkdec) {

        pkout = (*pkdec) + ctx->raw_crypto_publickeybytes;

        if (pk)
            pkin = pk + crypto_publickeybytes;
        if (sk)
            skin = sk + crypto_secretkeybytes;

        int decspki = decode_SubjectPublicKeyInfo(ctx, encoding, skin, pkin, pkout, withoptional);
        if (decspki <= 0) return QSC_ENC_ERR;

        pkout -= decspki;
        pkoutbytes -= decspki;
        wrpk += decspki;

        if (ctx->raw_crypto_publickey_header_bytes > 0) {
            memmove(pkout - ctx->raw_crypto_publickey_header_bytes, ctx->raw_crypto_publickey_header, ctx->raw_crypto_publickey_header_bytes);
            pkout -= ctx->raw_crypto_publickey_header_bytes;
            pkoutbytes -= ctx->raw_crypto_publickey_header_bytes;
            wrpk += ctx->raw_crypto_publickey_header_bytes;
        }

        if (wrpk != ctx->raw_crypto_publickeybytes)
            return QSC_ENC_ERR;
        
    }

    if (skdec) {

        skout = (*skdec) + ctx->raw_crypto_secretkeybytes;
        pkin = NULL; skin = NULL;

        if (sk)
            skin = sk + crypto_secretkeybytes;
        if (pk)
            pkin = pk + crypto_publickeybytes;

        int decprik = decode_PrivateKeyInfo(ctx, encoding, skin, pkin, pkout, skout, withoptional);
        if (decprik <= 0) return QSC_ENC_ERR;

        skout -= decprik;
        skoutbytes -= decprik;
        wrsk += decprik;

        if (ctx->raw_crypto_secretkey_header_bytes > 0) {
            memmove(skout - ctx->raw_crypto_secretkey_header_bytes, ctx->raw_crypto_secretkey_header, ctx->raw_crypto_secretkey_header_bytes);
            skout -= ctx->raw_crypto_secretkey_header_bytes;
            skoutbytes -= ctx->raw_crypto_secretkey_header_bytes;
            wrsk += ctx->raw_crypto_secretkey_header_bytes;
        }

        if (wrsk != ctx->raw_crypto_secretkeybytes)
            return QSC_ENC_ERR;

    }
    return QSC_ENC_OK;
}
