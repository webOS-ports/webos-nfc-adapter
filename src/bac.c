/* @@@LICENSE
*
* Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "bac.h"

#define DES_BLOCK_LEN	8

/* ---- low-level crypto helpers, all fixed-size/no-padding (SM does its
 * own ISO 7816-4 padding) ---- */

static void sha1(const guint8 *data, gsize len, guint8 out[SHA_DIGEST_LENGTH])
{
	SHA1(data, len, out);
}

/* Runs a cipher one-shot with padding disabled; buf is in-place, len must
 * already be a multiple of the block size. Returns FALSE on any OpenSSL
 * error (bad key length, unavailable algorithm, etc). */
static gboolean evp_crypt(const EVP_CIPHER *cipher, gboolean encrypt, const guint8 *key,
                          const guint8 *iv, const guint8 *in, gsize len, guint8 *out)
{
	EVP_CIPHER_CTX *ctx;
	int outlen1 = 0, outlen2 = 0;
	gboolean ok;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return FALSE;

	ok = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, encrypt) &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) &&
	    EVP_CipherUpdate(ctx, out, &outlen1, in, (int) len) &&
	    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);

	EVP_CIPHER_CTX_free(ctx);

	return ok && (gsize)(outlen1 + outlen2) == len;
}

/* 3-key 3DES-CBC (K1|K2|K1, from a 16-byte two-key BAC key), IV as given */
static gboolean des3_cbc(gboolean encrypt, const guint8 key16[BAC_KEY_LEN],
                         const guint8 iv[DES_BLOCK_LEN], const guint8 *in, gsize len,
                         guint8 *out)
{
	guint8 key24[24];

	memcpy(key24, key16, BAC_KEY_LEN);
	memcpy(key24 + BAC_KEY_LEN, key16, DES_BLOCK_LEN);

	return evp_crypt(EVP_des_ede3_cbc(), encrypt, key24, iv, in, len, out);
}

/*
 * Single DES, needed for the retail MAC's inner steps. This build's
 * OpenSSL is configured with no-legacy (single DES lives in the "legacy"
 * provider since 3.0, and that provider isn't built at all here), so
 * EVP_des_cbc()/EVP_des_ecb() are not an option. Used instead: 3DES-EDE
 * with all three keys equal is exactly single DES (encrypt-decrypt-encrypt
 * with the same key cancels the middle two steps), and EDE3 stays in the
 * always-available default provider.
 */
static gboolean des_cbc(const guint8 key8[DES_BLOCK_LEN], const guint8 iv[DES_BLOCK_LEN],
                        const guint8 *in, gsize len, guint8 *out)
{
	guint8 key24[24];

	memcpy(key24, key8, DES_BLOCK_LEN);
	memcpy(key24 + DES_BLOCK_LEN, key8, DES_BLOCK_LEN);
	memcpy(key24 + 2 * DES_BLOCK_LEN, key8, DES_BLOCK_LEN);

	return evp_crypt(EVP_des_ede3_cbc(), TRUE, key24, iv, in, len, out);
}

static gboolean des_ecb(gboolean encrypt, const guint8 key8[DES_BLOCK_LEN],
                        const guint8 in[DES_BLOCK_LEN], guint8 out[DES_BLOCK_LEN])
{
	/* ECB ignores the IV, but EVP still wants a non-NULL pointer shape */
	guint8 iv[DES_BLOCK_LEN] = { 0 };
	guint8 key24[24];

	memcpy(key24, key8, DES_BLOCK_LEN);
	memcpy(key24 + DES_BLOCK_LEN, key8, DES_BLOCK_LEN);
	memcpy(key24 + 2 * DES_BLOCK_LEN, key8, DES_BLOCK_LEN);

	return evp_crypt(EVP_des_ede3_ecb(), encrypt, key24, iv, in, DES_BLOCK_LEN, out);
}

/* ISO/IEC 9797-1 padding method 2: unconditional - always adds at least
 * one byte, a full extra block when data is already block-aligned. */
static GByteArray *iso_pad(const guint8 *data, gsize len)
{
	GByteArray *out = g_byte_array_new();
	gsize pad = DES_BLOCK_LEN - (len % DES_BLOCK_LEN);
	guint8 marker = 0x80;

	g_byte_array_append(out, data, len);
	g_byte_array_append(out, &marker, 1);
	for (gsize n = 1; n < pad; n++) {
		guint8 zero = 0x00;
		g_byte_array_append(out, &zero, 1);
	}
	return out;
}

/* ISO/IEC 9797-1 MAC algorithm 3 ("retail MAC"): DES-CBC-MAC with K1 over
 * the padded input, then a decrypt/encrypt with K2/K1 on the last block.
 * Returns FALSE (leaving *out unset) on any underlying crypto failure -
 * callers must check this rather than trust a MAC that was never really
 * computed. */
static gboolean retail_mac(const guint8 key16[BAC_KEY_LEN], const guint8 *data, gsize len,
                           guint8 out[DES_BLOCK_LEN])
{
	GByteArray *padded = iso_pad(data, len);
	guint8 iv0[DES_BLOCK_LEN] = { 0 };
	guint8 *cbc_out = g_malloc(padded->len);
	guint8 last[DES_BLOCK_LEN], decrypted[DES_BLOCK_LEN];
	gboolean ok;

	ok = des_cbc(key16, iv0, padded->data, padded->len, cbc_out);
	memcpy(last, cbc_out + padded->len - DES_BLOCK_LEN, DES_BLOCK_LEN);
	g_free(cbc_out);
	g_byte_array_free(padded, TRUE);

	if (!ok)
		return FALSE;

	return des_ecb(FALSE, key16 + DES_BLOCK_LEN, last, decrypted) &&
	      des_ecb(TRUE, key16, decrypted, out);
}

/* Constant-time-ish compare - not on a network timing-attack path (the
 * chip, not a remote party, holds the other side of this secret), but
 * cheap to do properly anyway. */
static gboolean bytes_equal(const guint8 *a, const guint8 *b, gsize len)
{
	guint8 diff = 0;

	for (gsize n = 0; n < len; n++)
		diff |= a[n] ^ b[n];
	return diff == 0;
}

/* Odd-parity adjustment (DES key parity: LSB of each byte set so the byte
 * has odd bit-parity) - part of the 9303-11 9.7.1 key derivation function */
static void set_key_parity(guint8 *key, gsize len)
{
	for (gsize n = 0; n < len; n++) {
		guint8 v = key[n] & 0xFE;
		int ones = 0;

		for (int b = 0; b < 8; b++)
			if (v & (1 << b))
				ones++;
		key[n] = v | ((ones % 2) ? 0 : 1);
	}
}

/*
 * 9303-11 9.7.1: Ka|Kb = most significant 16 bytes of SHA-1(Kseed || c),
 * c = 1 for KEnc, c = 2 for KMAC/KSMac, parity-adjusted. Kseed is always
 * BAC_KEY_LEN bytes here - both the MRZ-derived seed and the KIFD^KICC
 * session seed are that size by construction, so the input width isn't a
 * parameter worth generalizing.
 */
static void kdf(const guint8 kseed[BAC_KEY_LEN], guint32 c, guint8 out[BAC_KEY_LEN])
{
	guint8 d[BAC_KEY_LEN + 4];
	guint8 digest[SHA_DIGEST_LENGTH];

	memcpy(d, kseed, BAC_KEY_LEN);
	d[BAC_KEY_LEN + 0] = (guint8)(c >> 24);
	d[BAC_KEY_LEN + 1] = (guint8)(c >> 16);
	d[BAC_KEY_LEN + 2] = (guint8)(c >> 8);
	d[BAC_KEY_LEN + 3] = (guint8)(c);

	sha1(d, sizeof(d), digest);
	memcpy(out, digest, BAC_KEY_LEN);
	set_key_parity(out, BAC_KEY_LEN);
}

/* ---- MRZ check digit (ICAO 9303-3 Appendix A: 7-3-1 weighted mod 10,
 * '0'-'9' at face value, 'A'-'Z' as 10-35, '<' as 0) ---- */

static int mrz_char_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 10;
	if (c == '<')
		return 0;
	return -1;
}

static gboolean mrz_check_digit(const char *field, gsize len, char *digit_out)
{
	static const int weights[3] = { 7, 3, 1 };
	int sum = 0;

	for (gsize n = 0; n < len; n++) {
		int v = mrz_char_value(field[n]);

		if (v < 0)
			return FALSE;
		sum += v * weights[n % 3];
	}
	*digit_out = (char)('0' + (sum % 10));
	return TRUE;
}

/*
 * Document number is a 9-character MRZ field: the raw value, uppercased,
 * padded on the right with '<' to 9 characters. Longer document numbers
 * don't fit BAC's document-number field at all (some issuers's TD1 cards
 * put the overflow elsewhere in the MRZ) - not handled here.
 */
#define MRZ_DOC_NUMBER_LEN	9
#define MRZ_DATE_LEN		6

gboolean bac_mrz_sha1(const char *document_number, const char *date_of_birth,
                      const char *date_of_expiry, guint8 out[SHA_DIGEST_LENGTH])
{
	char doc[MRZ_DOC_NUMBER_LEN];
	char mrz_info[3 * MRZ_DOC_NUMBER_LEN]; /* generous; actual use is 24 bytes */
	gsize pos = 0;
	char digit;

	if (!document_number || !date_of_birth || !date_of_expiry)
		return FALSE;
	if (strlen(document_number) == 0 || strlen(document_number) > MRZ_DOC_NUMBER_LEN)
		return FALSE;
	if (strlen(date_of_birth) != MRZ_DATE_LEN || strlen(date_of_expiry) != MRZ_DATE_LEN)
		return FALSE;

	memset(doc, '<', sizeof(doc));
	for (gsize n = 0; n < strlen(document_number); n++)
		doc[n] = g_ascii_toupper(document_number[n]);

	memcpy(mrz_info + pos, doc, MRZ_DOC_NUMBER_LEN);
	pos += MRZ_DOC_NUMBER_LEN;
	if (!mrz_check_digit(doc, MRZ_DOC_NUMBER_LEN, &digit))
		return FALSE;
	mrz_info[pos++] = digit;

	memcpy(mrz_info + pos, date_of_birth, MRZ_DATE_LEN);
	pos += MRZ_DATE_LEN;
	if (!mrz_check_digit(date_of_birth, MRZ_DATE_LEN, &digit))
		return FALSE;
	mrz_info[pos++] = digit;

	memcpy(mrz_info + pos, date_of_expiry, MRZ_DATE_LEN);
	pos += MRZ_DATE_LEN;
	if (!mrz_check_digit(date_of_expiry, MRZ_DATE_LEN, &digit))
		return FALSE;
	mrz_info[pos++] = digit;

	sha1((const guint8 *) mrz_info, pos, out);
	memset(mrz_info, 0, sizeof(mrz_info));
	return TRUE;
}

gboolean bac_derive_static_keys(const char *document_number, const char *date_of_birth,
                                const char *date_of_expiry, BacStaticKeys *keys_out)
{
	guint8 digest[SHA_DIGEST_LENGTH];
	guint8 kseed[BAC_KEY_LEN]; /* most significant 16 bytes of the SHA-1 digest */

	if (!bac_mrz_sha1(document_number, date_of_birth, date_of_expiry, digest))
		return FALSE;
	memcpy(kseed, digest, BAC_KEY_LEN);

	kdf(kseed, 1, keys_out->kenc);
	kdf(kseed, 2, keys_out->kmac);

	memset(kseed, 0, sizeof(kseed));
	return TRUE;
}

/* ---- APDU builders ---- */

static const guint8 emrtd_aid[] = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

GByteArray *bac_build_select_aid(void)
{
	GByteArray *apdu = g_byte_array_new();
	guint8 header[] = { 0x00, 0xA4, 0x04, 0x0C, (guint8) sizeof(emrtd_aid) };

	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, emrtd_aid, sizeof(emrtd_aid));
	return apdu;
}

GByteArray *bac_build_get_challenge(void)
{
	GByteArray *apdu = g_byte_array_new();
	guint8 cmd[] = { 0x00, 0x84, 0x00, 0x00, 0x08 };

	g_byte_array_append(apdu, cmd, sizeof(cmd));
	return apdu;
}

GByteArray *bac_build_mutual_authenticate(const BacStaticKeys *keys, const guint8 rnd_icc[8],
                                          BacChallenge *challenge_out)
{
	guint8 s[8 + 8 + BAC_KEY_LEN];
	guint8 eifd[sizeof(s)];
	guint8 mifd[DES_BLOCK_LEN];
	guint8 iv0[DES_BLOCK_LEN] = { 0 };
	GByteArray *apdu;
	guint8 cmd_data_len = (guint8)(sizeof(eifd) + sizeof(mifd)); /* 40: EIFD + MIFD */
	guint8 header[] = { 0x00, 0x82, 0x00, 0x00, cmd_data_len };
	guint8 le = cmd_data_len;

	if (RAND_bytes(challenge_out->rnd_ifd, sizeof(challenge_out->rnd_ifd)) != 1)
		return NULL;
	if (RAND_bytes(challenge_out->k_ifd, sizeof(challenge_out->k_ifd)) != 1)
		return NULL;

	memcpy(s, challenge_out->rnd_ifd, 8);
	memcpy(s + 8, rnd_icc, 8);
	memcpy(s + 16, challenge_out->k_ifd, BAC_KEY_LEN);

	if (!des3_cbc(TRUE, keys->kenc, iv0, s, sizeof(s), eifd))
		return NULL;
	if (!retail_mac(keys->kmac, eifd, sizeof(eifd), mifd))
		return NULL;

	apdu = g_byte_array_new();
	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, eifd, sizeof(eifd));
	g_byte_array_append(apdu, mifd, sizeof(mifd));
	g_byte_array_append(apdu, &le, 1);
	return apdu;
}

gboolean bac_process_mutual_authenticate_response(const BacStaticKeys *keys,
                                                  const BacChallenge *challenge,
                                                  const guint8 rnd_icc[8],
                                                  const guint8 *response, gsize response_len,
                                                  BacSession *session_out)
{
	guint8 eicc[32], mic_expect[DES_BLOCK_LEN];
	guint8 r[32];
	guint8 iv0[DES_BLOCK_LEN] = { 0 };
	guint8 kseed[BAC_KEY_LEN];

	/* 32 bytes encrypted data (RND.ICC|RND.IFD|K.ICC) + 8 bytes MAC */
	if (response_len != 40)
		return FALSE;

	memcpy(eicc, response, 32);
	if (!retail_mac(keys->kmac, eicc, sizeof(eicc), mic_expect))
		return FALSE;
	if (!bytes_equal(mic_expect, response + 32, DES_BLOCK_LEN))
		return FALSE;

	if (!des3_cbc(FALSE, keys->kenc, iv0, eicc, sizeof(eicc), r))
		return FALSE;

	/* r = RND.ICC | RND.IFD | K.ICC - both randoms must match what we
	 * sent/received, or this isn't really the chip we authenticated to */
	if (!bytes_equal(r, rnd_icc, 8))
		return FALSE;
	if (!bytes_equal(r + 8, challenge->rnd_ifd, 8))
		return FALSE;

	for (int n = 0; n < BAC_KEY_LEN; n++)
		kseed[n] = challenge->k_ifd[n] ^ r[16 + n];

	kdf(kseed, 1, session_out->ks_enc);
	kdf(kseed, 2, session_out->ks_mac);

	memcpy(session_out->ssc, rnd_icc + 4, 4);
	memcpy(session_out->ssc + 4, challenge->rnd_ifd + 4, 4);

	memset(kseed, 0, sizeof(kseed));
	memset(r, 0, sizeof(r));
	return TRUE;
}

/* ---- BER-TLV length parsing (shared by the public 1-byte-tag helper and
 * the DG1 parser's 2-byte-tag lookup) ---- */

static gboolean ber_length(const guint8 *p, gsize avail, gsize *header_len_out,
                           gsize *content_len_out)
{
	if (avail < 1)
		return FALSE;

	if (p[0] < 0x80) {
		*header_len_out = 1;
		*content_len_out = p[0];
		return TRUE;
	}
	if (p[0] == 0x81) {
		if (avail < 2)
			return FALSE;
		*header_len_out = 2;
		*content_len_out = p[1];
		return TRUE;
	}
	if (p[0] == 0x82) {
		if (avail < 3)
			return FALSE;
		*header_len_out = 3;
		*content_len_out = ((gsize) p[1] << 8) | p[2];
		return TRUE;
	}
	/* Longer forms don't occur in eMRTD data groups */
	return FALSE;
}

gboolean bac_ber_tlv_header(const guint8 *data, gsize len, gsize *header_len_out,
                            gsize *content_len_out)
{
	gsize len_header_len, content_len;

	if (len < 2)
		return FALSE;
	/* data[0] is the (assumed single-byte) tag */
	if (!ber_length(data + 1, len - 1, &len_header_len, &content_len))
		return FALSE;

	*header_len_out = 1 + len_header_len;
	*content_len_out = content_len;
	return TRUE;
}

gchar *bac_parse_dg1_mrz(const guint8 *dg1, gsize dg1_len)
{
	gsize outer_header, outer_content;
	gsize pos, inner_header, inner_content;

	if (dg1_len < 2 || dg1[0] != 0x61)
		return NULL;
	if (!bac_ber_tlv_header(dg1, dg1_len, &outer_header, &outer_content))
		return NULL;
	if (outer_header + outer_content > dg1_len)
		return NULL;

	pos = outer_header;
	if (pos + 2 > dg1_len || dg1[pos] != 0x5F || dg1[pos + 1] != 0x1F)
		return NULL;

	if (!ber_length(dg1 + pos + 2, dg1_len - pos - 2, &inner_header, &inner_content))
		return NULL;
	pos += 2 + inner_header;
	if (pos + inner_content > dg1_len)
		return NULL;

	return g_strndup((const gchar *) dg1 + pos, inner_content);
}

/* ---- MRZ field parsing ---- */

/* Copies up to len bytes from src, stopping at the first '<' fill
 * character or out_cap-1, whichever comes first - every fixed-width MRZ
 * field except the name is right-padded with '<', never contains one. */
static void mrz_trim_copy(const gchar *src, gsize len, gchar *out, gsize out_cap)
{
	gsize n = 0;

	while (n < len && n + 1 < out_cap && src[n] != '<')
		n++;
	memcpy(out, src, n);
	out[n] = '\0';
}

/* Name field: primary identifier (surname), then "<<", then secondary
 * identifier (given names) - single '<' within either part is a space.
 * No "<<" at all means no secondary identifier was present. */
static void mrz_decode_name(const gchar *field, gsize len, gchar *surname_out, gsize surname_cap,
                            gchar *given_out, gsize given_cap)
{
	gsize sep = 0, n;

	while (sep + 1 < len && !(field[sep] == '<' && field[sep + 1] == '<'))
		sep++;
	if (sep + 1 >= len)
		sep = len;

	n = MIN(sep, surname_cap - 1);
	for (gsize i = 0; i < n; i++)
		surname_out[i] = (field[i] == '<') ? ' ' : field[i];
	surname_out[n] = '\0';
	g_strchomp(surname_out);

	given_out[0] = '\0';
	if (sep + 2 < len) {
		gsize glen = MIN(len - (sep + 2), given_cap - 1);

		for (gsize i = 0; i < glen; i++)
			given_out[i] = (field[sep + 2 + i] == '<') ? ' ' : field[sep + 2 + i];
		given_out[glen] = '\0';
		g_strchomp(given_out);
	}
}

#define MRZ_TD1_LEN	90
#define MRZ_TD3_LEN	88

gboolean bac_parse_mrz_fields(const gchar *mrz, MrzFields *out)
{
	gsize len;
	char digit;

	if (!mrz || !out)
		return FALSE;

	len = strlen(mrz);
	memset(out, 0, sizeof(*out));

	if (len == MRZ_TD1_LEN) {
		/* Line 1 [0-29]: type(2) state(3) docnum(9) check(1) optional(15)
		 * Line 2 [30-59]: dob(6) check(1) sex(1) expiry(6) check(1)
		 *                 nationality(3) optional(11) composite(1)
		 * Line 3 [60-89]: name(30) */
		mrz_trim_copy(mrz, 2, out->document_type, sizeof(out->document_type));
		mrz_trim_copy(mrz + 2, 3, out->issuing_state, sizeof(out->issuing_state));
		mrz_trim_copy(mrz + 5, 9, out->document_number, sizeof(out->document_number));
		out->document_number_check_ok = mrz_check_digit(mrz + 5, 9, &digit) &&
		                                digit == mrz[14];

		mrz_trim_copy(mrz + 30, 6, out->date_of_birth, sizeof(out->date_of_birth));
		out->date_of_birth_check_ok = mrz_check_digit(mrz + 30, 6, &digit) &&
		                              digit == mrz[36];
		out->sex[0] = mrz[37];
		mrz_trim_copy(mrz + 38, 6, out->date_of_expiry, sizeof(out->date_of_expiry));
		out->date_of_expiry_check_ok = mrz_check_digit(mrz + 38, 6, &digit) &&
		                               digit == mrz[44];
		mrz_trim_copy(mrz + 45, 3, out->nationality, sizeof(out->nationality));

		mrz_decode_name(mrz + 60, 30, out->surname, sizeof(out->surname),
		                out->given_names, sizeof(out->given_names));
		return TRUE;
	}

	if (len == MRZ_TD3_LEN) {
		/* Line 1 [0-43]: type(2) state(3) name(39)
		 * Line 2 [44-87]: docnum(9) check(1) nationality(3) dob(6) check(1)
		 *                 sex(1) expiry(6) check(1) optional(14)
		 *                 optcheck(1) composite(1) */
		mrz_trim_copy(mrz, 2, out->document_type, sizeof(out->document_type));
		mrz_trim_copy(mrz + 2, 3, out->issuing_state, sizeof(out->issuing_state));
		mrz_decode_name(mrz + 5, 39, out->surname, sizeof(out->surname),
		                out->given_names, sizeof(out->given_names));

		mrz_trim_copy(mrz + 44, 9, out->document_number, sizeof(out->document_number));
		out->document_number_check_ok = mrz_check_digit(mrz + 44, 9, &digit) &&
		                                digit == mrz[53];
		mrz_trim_copy(mrz + 54, 3, out->nationality, sizeof(out->nationality));
		mrz_trim_copy(mrz + 57, 6, out->date_of_birth, sizeof(out->date_of_birth));
		out->date_of_birth_check_ok = mrz_check_digit(mrz + 57, 6, &digit) &&
		                              digit == mrz[63];
		out->sex[0] = mrz[64];
		mrz_trim_copy(mrz + 65, 6, out->date_of_expiry, sizeof(out->date_of_expiry));
		out->date_of_expiry_check_ok = mrz_check_digit(mrz + 65, 6, &digit) &&
		                               digit == mrz[71];
		return TRUE;
	}

	return FALSE;
}

/* ---- DG2 (facial photo) ---- */

static const guint8 jpeg_magic[] = { 0xFF, 0xD8, 0xFF };
static const guint8 jp2_magic[] = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A,
                                   0x87, 0x0A };
static const guint8 jp2_codestream_magic[] = { 0xFF, 0x4F, 0xFF, 0x51 };

static gssize find_bytes(const guint8 *haystack, gsize haystack_len,
                         const guint8 *needle, gsize needle_len)
{
	if (needle_len == 0 || haystack_len < needle_len)
		return -1;

	for (gsize n = 0; n <= haystack_len - needle_len; n++)
		if (memcmp(haystack + n, needle, needle_len) == 0)
			return (gssize) n;
	return -1;
}

GByteArray *bac_extract_dg2_photo(const guint8 *dg2, gsize dg2_len, const gchar **format_out)
{
	gssize pos;
	const gchar *format;
	GByteArray *photo;

	pos = find_bytes(dg2, dg2_len, jpeg_magic, sizeof(jpeg_magic));
	format = "jpeg";

	if (pos < 0) {
		pos = find_bytes(dg2, dg2_len, jp2_magic, sizeof(jp2_magic));
		format = "jpeg2000";
	}
	if (pos < 0) {
		pos = find_bytes(dg2, dg2_len, jp2_codestream_magic, sizeof(jp2_codestream_magic));
		format = "jpeg2000";
	}
	if (pos < 0)
		return NULL;

	photo = g_byte_array_new();
	g_byte_array_append(photo, dg2 + pos, (guint)(dg2_len - (gsize) pos));
	if (format_out)
		*format_out = format;
	return photo;
}

/* ---- Secure messaging ---- */

static void ssc_increment(guint8 ssc[BAC_SSC_LEN])
{
	for (int n = BAC_SSC_LEN - 1; n >= 0; n--)
		if (++ssc[n] != 0)
			break;
}

/* Appends a BER-TLV with a short-form length (data groups here are always
 * well under 128 bytes) */
static void append_tlv(GByteArray *out, guint8 tag, const guint8 *data, gsize len)
{
	guint8 hdr[2] = { tag, (guint8) len };

	g_byte_array_append(out, hdr, 2);
	if (len)
		g_byte_array_append(out, data, len);
}

GByteArray *bac_sm_protect(BacSession *session, guint8 cla, guint8 ins, guint8 p1, guint8 p2,
                           const guint8 *data, gsize data_len, gint le)
{
	guint8 header[4] = { (guint8)(cla | 0x0C), ins, p1, p2 };
	GByteArray *header_padded = iso_pad(header, sizeof(header));
	GByteArray *do87 = NULL, *do97 = NULL;
	GByteArray *m, *n, *apdu;
	guint8 mac[DES_BLOCK_LEN];
	guint8 lc;

	if (le > 255)
		return NULL;
	if (data_len > 223) /* keeps do87's short-form length (<=0x7F) valid */
		return NULL;

	if (data && data_len > 0) {
		GByteArray *padded = iso_pad(data, data_len);
		guint8 *enc = g_malloc(padded->len);
		guint8 pad_indicator = 0x01;
		GByteArray *enc_field;

		if (!des3_cbc(TRUE, session->ks_enc, (guint8[DES_BLOCK_LEN]) { 0 },
		             padded->data, padded->len, enc)) {
			g_free(enc);
			g_byte_array_free(padded, TRUE);
			g_byte_array_free(header_padded, TRUE);
			return NULL;
		}
		enc_field = g_byte_array_new();
		g_byte_array_append(enc_field, &pad_indicator, 1);
		g_byte_array_append(enc_field, enc, padded->len);

		do87 = g_byte_array_new();
		append_tlv(do87, 0x87, enc_field->data, enc_field->len);

		g_byte_array_free(enc_field, TRUE);
		g_free(enc);
		g_byte_array_free(padded, TRUE);
	}

	if (le >= 0) {
		guint8 le_byte = (guint8) le;

		do97 = g_byte_array_new();
		append_tlv(do97, 0x97, &le_byte, 1);
	}

	m = g_byte_array_new();
	g_byte_array_append(m, header_padded->data, header_padded->len);
	if (do87)
		g_byte_array_append(m, do87->data, do87->len);
	if (do97)
		g_byte_array_append(m, do97->data, do97->len);
	g_byte_array_free(header_padded, TRUE);

	ssc_increment(session->ssc);
	n = g_byte_array_new();
	g_byte_array_append(n, session->ssc, BAC_SSC_LEN);
	g_byte_array_append(n, m->data, m->len);
	g_byte_array_free(m, TRUE);

	if (!retail_mac(session->ks_mac, n->data, n->len, mac)) {
		g_byte_array_free(n, TRUE);
		if (do87)
			g_byte_array_free(do87, TRUE);
		if (do97)
			g_byte_array_free(do97, TRUE);
		return NULL;
	}
	g_byte_array_free(n, TRUE);

	lc = (guint8)((do87 ? do87->len : 0) + (do97 ? do97->len : 0) + 2 + DES_BLOCK_LEN);

	apdu = g_byte_array_new();
	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, &lc, 1);
	if (do87) {
		g_byte_array_append(apdu, do87->data, do87->len);
		g_byte_array_free(do87, TRUE);
	}
	if (do97) {
		g_byte_array_append(apdu, do97->data, do97->len);
		g_byte_array_free(do97, TRUE);
	}
	append_tlv(apdu, 0x8E, mac, DES_BLOCK_LEN);
	{
		guint8 trailing_le = 0x00;
		g_byte_array_append(apdu, &trailing_le, 1);
	}

	return apdu;
}

gboolean bac_sm_unprotect(BacSession *session, const guint8 *rapdu, gsize rapdu_len,
                          GByteArray **plaintext_out, guint16 *sw_out)
{
	gsize pos = 0;
	const guint8 *do87 = NULL; gsize do87_len = 0;
	const guint8 *do99 = NULL; gsize do99_len = 0;
	const guint8 *do8e = NULL; gsize do8e_len = 0;
	GByteArray *mac_input;
	guint8 mac[DES_BLOCK_LEN];

	*plaintext_out = NULL;

	/* Trailing SW1SW2 is only meaningful when the SM wrapper parsed; a
	 * transport-level short/garbage response has no SW to report */
	if (rapdu_len < 2)
		return FALSE;

	while (pos + 2 <= rapdu_len) {
		guint8 tag = rapdu[pos];
		gsize hlen, clen;

		if (!ber_length(rapdu + pos + 1, rapdu_len - pos - 1, &hlen, &clen))
			return FALSE;
		if (pos + 1 + hlen + clen > rapdu_len)
			return FALSE;

		if (tag == 0x87) { do87 = rapdu + pos; do87_len = 1 + hlen + clen; }
		else if (tag == 0x99) { do99 = rapdu + pos; do99_len = 1 + hlen + clen; }
		else if (tag == 0x8E) { do8e = rapdu + pos; do8e_len = 1 + hlen + clen; }
		/* Unknown DOs are skipped, not rejected - forward compatible */

		pos += 1 + hlen + clen;
	}

	if (!do99 || do99_len != 4 || !do8e || do8e_len != 2 + DES_BLOCK_LEN)
		return FALSE;

	ssc_increment(session->ssc);
	mac_input = g_byte_array_new();
	g_byte_array_append(mac_input, session->ssc, BAC_SSC_LEN);
	if (do87)
		g_byte_array_append(mac_input, do87, do87_len);
	g_byte_array_append(mac_input, do99, do99_len);

	{
		gboolean mac_ok = retail_mac(session->ks_mac, mac_input->data, mac_input->len, mac);
		g_byte_array_free(mac_input, TRUE);
		if (!mac_ok)
			return FALSE;
	}

	if (!bytes_equal(mac, do8e + 2, DES_BLOCK_LEN))
		return FALSE;

	*sw_out = (guint16)((do99[2] << 8) | do99[3]);

	if (do87) {
		/* do87 = tag, length header, 0x01 padding-indicator, encrypted
		 * data - the indicator byte is included in the TLV length */
		gsize hlen, clen;
		const guint8 *enc;
		gsize enc_len;
		guint8 *dec;
		gsize i;

		if (!ber_length(do87 + 1, do87_len - 1, &hlen, &clen) || clen < 1)
			return FALSE;
		if (do87[1 + hlen] != 0x01) /* only "padded, no chaining" is defined here */
			return FALSE;

		enc = do87 + 1 + hlen + 1;
		enc_len = clen - 1;

		if (enc_len == 0 || enc_len % DES_BLOCK_LEN != 0)
			return FALSE;

		dec = g_malloc(enc_len);
		if (!des3_cbc(FALSE, session->ks_enc, (guint8[DES_BLOCK_LEN]) { 0 },
		             enc, enc_len, dec)) {
			g_free(dec);
			return FALSE;
		}

		i = enc_len;
		while (i > 0 && dec[i - 1] == 0x00)
			i--;
		if (i == 0 || dec[i - 1] != 0x80) {
			g_free(dec);
			return FALSE;
		}

		*plaintext_out = g_byte_array_new();
		g_byte_array_append(*plaintext_out, dec, i - 1);
		g_free(dec);
	}

	return TRUE;
}

// vim:ts=4:sw=4:noexpandtab
