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
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include "bac.h"
#include "pace.h"

#define AES_BLOCK_LEN	16
#define EC_COORD_LEN	32	/* brainpoolP256r1 field element size */
#define EC_PUB_LEN	(1 + 2 * EC_COORD_LEN)	/* uncompressed point, 0x04 || x || y */

/* id-PACE-ECDH-GM-AES-CBC-CMAC-128, ICAO 9303 Supplement Appendix G.1.1 */
static const guint8 pace_oid[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02 };

struct PaceExchange {
	guint8 kpi[PACE_KEY_LEN];
	guint8 nonce_s[AES_BLOCK_LEN];

	BN_CTX *ctx;
	EC_GROUP *group;	/* standardized brainpoolP256r1 */
	BIGNUM *priv1;		/* round 2: our ephemeral mapping key */
	EC_GROUP *group2;	/* round 2 result: same curve, generator G~ */
	BIGNUM *priv2;		/* round 3: our ephemeral key-agreement key */
	guint8 my_pub2[EC_PUB_LEN];
	guint8 chip_pub2[EC_PUB_LEN];

	PaceSession session;	/* usable once round 3 completes */
};

/* ---- KDF: TR-03110 A.2.3 - SHA-1(K || r || c), no DES parity (that's a
 * 3DES/BAC-specific extra step - see bac.c's kdf(), which this is not). K
 * is whatever-length here (a CAN string or a 20-byte MRZ digest), unlike
 * BAC's always-16-byte kseed, so this can't just call bac.c's version. ---- */
static void pace_kdf(const guint8 *k, gsize k_len, guint32 c, guint8 out[PACE_KEY_LEN])
{
	guint8 *d = g_malloc(k_len + 4);
	guint8 digest[SHA_DIGEST_LENGTH];

	memcpy(d, k, k_len);
	d[k_len + 0] = (guint8)(c >> 24);
	d[k_len + 1] = (guint8)(c >> 16);
	d[k_len + 2] = (guint8)(c >> 8);
	d[k_len + 3] = (guint8)(c);

	SHA1(d, k_len + 4, digest);
	memcpy(out, digest, PACE_KEY_LEN);
	g_free(d);
}

GByteArray *pace_derive_k_can(const char *can)
{
	GByteArray *k;

	if (!can || !can[0])
		return NULL;

	k = g_byte_array_new();
	g_byte_array_append(k, (const guint8 *) can, (guint) strlen(can));
	return k;
}

GByteArray *pace_derive_k_mrz(const char *document_number, const char *date_of_birth,
                              const char *date_of_expiry)
{
	guint8 digest[SHA_DIGEST_LENGTH];
	GByteArray *k;

	if (!bac_mrz_sha1(document_number, date_of_birth, date_of_expiry, digest))
		return NULL;

	k = g_byte_array_new();
	g_byte_array_append(k, digest, sizeof(digest));
	return k;
}

/* ---- AES-CBC (no padding - all PACE ciphertext here is already
 * block-aligned) and truncated AES-CMAC-128, the two primitives PACE's
 * secure messaging and Mutual Authenticate steps both need ---- */

static gboolean aes_cbc(gboolean encrypt, const guint8 key[PACE_KEY_LEN],
                        const guint8 iv[AES_BLOCK_LEN], const guint8 *in, gsize len, guint8 *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int outlen1 = 0, outlen2 = 0;
	gboolean ok;

	if (!ctx)
		return FALSE;

	ok = EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, encrypt) &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) &&
	    EVP_CipherUpdate(ctx, out, &outlen1, in, (int) len) &&
	    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);

	EVP_CIPHER_CTX_free(ctx);
	return ok && (gsize)(outlen1 + outlen2) == len;
}

/* AES-128-ECB single block - used only to compute the SM encryption IV,
 * E(KSenc, SSC) (9303-11 Annex F.4.2.1), not for bulk data. */
static gboolean aes_ecb_encrypt_block(const guint8 key[PACE_KEY_LEN],
                                      const guint8 in[AES_BLOCK_LEN], guint8 out[AES_BLOCK_LEN])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int outlen1 = 0, outlen2 = 0;
	gboolean ok;

	if (!ctx)
		return FALSE;

	ok = EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, 1) &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) &&
	    EVP_CipherUpdate(ctx, out, &outlen1, in, AES_BLOCK_LEN) &&
	    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);

	EVP_CIPHER_CTX_free(ctx);
	return ok && outlen1 + outlen2 == AES_BLOCK_LEN;
}

/* Full (16-byte) AES-CMAC - callers needing the 8-byte authentication
 * token truncate the result themselves (9303-11 Annex A.2.4/F.4.2.2 both
 * truncate, but to different things: a token vs a MAC datagram prefix). */
static gboolean aes_cmac(const guint8 key[PACE_KEY_LEN], const guint8 *data, gsize len,
                         guint8 out[AES_BLOCK_LEN])
{
	size_t outlen = 0;

	return EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL, key, PACE_KEY_LEN,
	                 data, len, out, AES_BLOCK_LEN, &outlen) != NULL && outlen == AES_BLOCK_LEN;
}

static gboolean bytes_equal(const guint8 *a, const guint8 *b, gsize len)
{
	guint8 diff = 0;

	for (gsize n = 0; n < len; n++)
		diff |= a[n] ^ b[n];
	return diff == 0;
}

/* ---- Dynamic Authentication Data (7C) helpers: every GA round wraps its
 * single data object in an outer 7C, always short-form length here (PACE's
 * objects top out at 67 bytes) ---- */

static GByteArray *wrap_7c(guint8 inner_tag, const guint8 *data, gsize len)
{
	GByteArray *out = g_byte_array_new();
	guint8 hdr[2] = { 0x7C, (guint8)(len + 2) };
	guint8 inner_hdr[2] = { inner_tag, (guint8) len };

	g_byte_array_append(out, hdr, 2);
	g_byte_array_append(out, inner_hdr, 2);
	if (len)
		g_byte_array_append(out, data, len);
	return out;
}

/* Finds tag within a 7C-wrapped response; *content_out points into resp
 * (not copied). Returns FALSE if resp isn't a well-formed short-form 7C. */
static gboolean find_in_7c(const guint8 *resp, gsize len, guint8 tag,
                           const guint8 **content_out, gsize *content_len_out)
{
	gsize pos;

	if (len < 2 || resp[0] != 0x7C || resp[1] >= 0x80)
		return FALSE;
	if ((gsize)(resp[1] + 2) > len)
		return FALSE;

	pos = 2;
	while (pos + 2 <= (gsize)(resp[1] + 2)) {
		guint8 t = resp[pos];
		guint8 l = resp[pos + 1];

		if (l >= 0x80 || pos + 2 + l > (gsize)(resp[1] + 2))
			return FALSE;
		if (t == tag) {
			*content_out = resp + pos + 2;
			*content_len_out = l;
			return TRUE;
		}
		pos += 2 + l;
	}
	return FALSE;
}

/* ---- MSE:Set AT / GA APDU builders ---- */

GByteArray *pace_build_mse_set_at(gboolean use_can)
{
	GByteArray *apdu = g_byte_array_new();
	guint8 header[] = { 0x00, 0x22, 0xC1, 0xA4 };
	guint8 oid_tlv[2] = { 0x80, (guint8) sizeof(pace_oid) };
	guint8 pwd_tlv[3] = { 0x83, 0x01, (guint8)(use_can ? 0x02 : 0x01) };
	guint8 lc = (guint8)(sizeof(oid_tlv) + sizeof(pace_oid) + sizeof(pwd_tlv));

	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, &lc, 1);
	g_byte_array_append(apdu, oid_tlv, sizeof(oid_tlv));
	g_byte_array_append(apdu, pace_oid, sizeof(pace_oid));
	g_byte_array_append(apdu, pwd_tlv, sizeof(pwd_tlv));
	return apdu;
}

/* Every GA round but the last uses command chaining (CLA 0x10) since more
 * rounds follow; only Mutual Authenticate (built separately) uses 0x00. */
static GByteArray *build_ga(guint8 inner_tag, const guint8 *data, gsize len)
{
	GByteArray *dad = wrap_7c(inner_tag, data, len);
	GByteArray *apdu = g_byte_array_new();
	guint8 header[] = { 0x10, 0x86, 0x00, 0x00 };
	guint8 lc = (guint8) dad->len;
	guint8 le = 0x00;

	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, &lc, 1);
	g_byte_array_append(apdu, dad->data, dad->len);
	g_byte_array_append(apdu, &le, 1);
	g_byte_array_free(dad, TRUE);
	return apdu;
}

GByteArray *pace_build_get_nonce(void)
{
	/* Genuinely empty 7C (no inner DO at all) - unlike every later round,
	 * which always wraps one, so this doesn't go through build_ga(). */
	GByteArray *apdu = g_byte_array_new();
	guint8 cmd[] = { 0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00 };

	g_byte_array_append(apdu, cmd, sizeof(cmd));
	return apdu;
}

PaceExchange *pace_exchange_new(const GByteArray *k)
{
	PaceExchange *pace;
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
	BN_CTX *ctx = BN_CTX_new();

	if (!group || !ctx) {
		if (group)
			EC_GROUP_free(group);
		if (ctx)
			BN_CTX_free(ctx);
		return NULL;
	}

	pace = g_new0(PaceExchange, 1);
	pace->group = group;
	pace->ctx = ctx;
	pace_kdf(k->data, k->len, 3, pace->kpi);
	return pace;
}

void pace_exchange_free(PaceExchange *pace)
{
	if (!pace)
		return;
	if (pace->priv1)
		BN_clear_free(pace->priv1);
	if (pace->priv2)
		BN_clear_free(pace->priv2);
	if (pace->group2)
		EC_GROUP_free(pace->group2);
	if (pace->group)
		EC_GROUP_free(pace->group);
	if (pace->ctx)
		BN_CTX_free(pace->ctx);
	memset(pace, 0, sizeof(*pace));
	g_free(pace);
}

gboolean pace_process_nonce_response(PaceExchange *pace, const guint8 *resp, gsize len)
{
	const guint8 *z;
	gsize z_len;

	if (!find_in_7c(resp, len, 0x80, &z, &z_len) || z_len != AES_BLOCK_LEN)
		return FALSE;

	return aes_cbc(FALSE, pace->kpi, (guint8[AES_BLOCK_LEN]) { 0 }, z, AES_BLOCK_LEN,
	              pace->nonce_s);
}

/* Serializes an EC_POINT as an uncompressed octet string, 0x04 || x || y. */
static gboolean point_to_bytes(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx,
                               guint8 out[EC_PUB_LEN])
{
	return EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, out, EC_PUB_LEN,
	                          ctx) == EC_PUB_LEN;
}

static EC_POINT *point_from_bytes(const EC_GROUP *group, const guint8 *data, gsize len,
                                  BN_CTX *ctx)
{
	EC_POINT *point;

	if (len != EC_PUB_LEN || data[0] != 0x04)
		return NULL;

	point = EC_POINT_new(group);
	if (!point)
		return NULL;
	if (!EC_POINT_oct2point(group, point, data, len, ctx)) {
		EC_POINT_free(point);
		return NULL;
	}
	return point;
}

/* Random scalar in [1, order-1] - BN_rand_range's [0, order) can return 0
 * with vanishing (~2^-256) probability; not worth a retry loop for that. */
static BIGNUM *random_scalar(const BIGNUM *order)
{
	BIGNUM *r = BN_new();

	if (!r)
		return NULL;
	if (!BN_rand_range(r, order)) {
		BN_free(r);
		return NULL;
	}
	return r;
}

GByteArray *pace_build_map_nonce(PaceExchange *pace)
{
	EC_POINT *pub1;
	guint8 pub1_bytes[EC_PUB_LEN];
	GByteArray *apdu;

	pace->priv1 = random_scalar(EC_GROUP_get0_order(pace->group));
	if (!pace->priv1)
		return NULL;

	pub1 = EC_POINT_new(pace->group);
	if (!pub1)
		return NULL;
	if (!EC_POINT_mul(pace->group, pub1, pace->priv1, NULL, NULL, pace->ctx) ||
	   !point_to_bytes(pace->group, pub1, pace->ctx, pub1_bytes)) {
		EC_POINT_free(pub1);
		return NULL;
	}
	EC_POINT_free(pub1);

	apdu = build_ga(0x81, pub1_bytes, sizeof(pub1_bytes));
	return apdu;
}

gboolean pace_process_map_nonce_response(PaceExchange *pace, const guint8 *resp, gsize len)
{
	const guint8 *chip_pub1_bytes;
	gsize chip_pub1_len;
	EC_POINT *chip_pub1 = NULL, *h = NULL, *sg = NULL, *gtilde = NULL;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, *s = NULL;
	const BIGNUM *order, *cofactor;
	gboolean ok = FALSE;

	if (!find_in_7c(resp, len, 0x82, &chip_pub1_bytes, &chip_pub1_len))
		return FALSE;

	chip_pub1 = point_from_bytes(pace->group, chip_pub1_bytes, chip_pub1_len, pace->ctx);
	h = EC_POINT_new(pace->group);
	sg = EC_POINT_new(pace->group);
	gtilde = EC_POINT_new(pace->group);
	s = BN_bin2bn(pace->nonce_s, sizeof(pace->nonce_s), NULL);
	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!chip_pub1 || !h || !sg || !gtilde || !s || !p || !a || !b)
		goto out;

	/* H = our mapping priv * chip's mapping pub (== chip's priv * our
	 * pub - standard ECDH, either side computes the same point) */
	if (!EC_POINT_mul(pace->group, h, NULL, chip_pub1, pace->priv1, pace->ctx))
		goto out;
	/* s*G */
	if (!EC_POINT_mul(pace->group, sg, s, NULL, NULL, pace->ctx))
		goto out;
	/* G~ = s*G + H (generic mapping, TR-03110 4.3.2) */
	if (!EC_POINT_add(pace->group, gtilde, sg, h, pace->ctx))
		goto out;

	if (!EC_GROUP_get_curve(pace->group, p, a, b, pace->ctx))
		goto out;
	order = EC_GROUP_get0_order(pace->group);
	cofactor = EC_GROUP_get0_cofactor(pace->group);

	pace->group2 = EC_GROUP_new_curve_GFp(p, a, b, pace->ctx);
	if (!pace->group2 || !EC_GROUP_set_generator(pace->group2, gtilde, order, cofactor))
		goto out;

	ok = TRUE;
out:
	if (chip_pub1)
		EC_POINT_free(chip_pub1);
	if (h)
		EC_POINT_free(h);
	if (sg)
		EC_POINT_free(sg);
	if (gtilde)
		EC_POINT_free(gtilde);
	if (s)
		BN_clear_free(s);
	if (p)
		BN_free(p);
	if (a)
		BN_free(a);
	if (b)
		BN_free(b);
	if (!ok && pace->group2) {
		EC_GROUP_free(pace->group2);
		pace->group2 = NULL;
	}
	return ok;
}

GByteArray *pace_build_key_agreement(PaceExchange *pace)
{
	EC_POINT *pub2;
	gboolean ok;

	pace->priv2 = random_scalar(EC_GROUP_get0_order(pace->group2));
	if (!pace->priv2)
		return NULL;

	pub2 = EC_POINT_new(pace->group2);
	if (!pub2)
		return NULL;
	/* multiplies by group2's generator, i.e. G~, since we passed NULL
	 * for the explicit-point argument */
	ok = EC_POINT_mul(pace->group2, pub2, pace->priv2, NULL, NULL, pace->ctx) &&
	    point_to_bytes(pace->group2, pub2, pace->ctx, pace->my_pub2);
	EC_POINT_free(pub2);
	if (!ok)
		return NULL;

	return build_ga(0x83, pace->my_pub2, sizeof(pace->my_pub2));
}

gboolean pace_process_key_agreement_response(PaceExchange *pace, const guint8 *resp, gsize len,
                                             PaceSession *session_out)
{
	const guint8 *chip_pub2_bytes;
	gsize chip_pub2_len;
	EC_POINT *chip_pub2 = NULL, *shared = NULL;
	BIGNUM *x = NULL, *y = NULL;
	guint8 k[EC_COORD_LEN];
	gboolean ok = FALSE;

	if (!find_in_7c(resp, len, 0x84, &chip_pub2_bytes, &chip_pub2_len))
		return FALSE;
	if (chip_pub2_len != sizeof(pace->chip_pub2))
		return FALSE;
	memcpy(pace->chip_pub2, chip_pub2_bytes, chip_pub2_len);

	chip_pub2 = point_from_bytes(pace->group2, chip_pub2_bytes, chip_pub2_len, pace->ctx);
	shared = EC_POINT_new(pace->group2);
	x = BN_new();
	y = BN_new();
	if (!chip_pub2 || !shared || !x || !y)
		goto out;

	if (!EC_POINT_mul(pace->group2, shared, NULL, chip_pub2, pace->priv2, pace->ctx))
		goto out;
	/* Only the x-coordinate feeds the KDF (TR-03110 A.2.3 note on ECKA) */
	if (!EC_POINT_get_affine_coordinates(pace->group2, shared, x, y, pace->ctx))
		goto out;
	if (BN_bn2binpad(x, k, sizeof(k)) != (int) sizeof(k))
		goto out;

	pace_kdf(k, sizeof(k), 1, pace->session.ks_enc);
	pace_kdf(k, sizeof(k), 2, pace->session.ks_mac);
	memset(pace->session.ssc, 0, PACE_SSC_LEN); /* TR-03110 F.5: new session starts at 0 */
	*session_out = pace->session;

	ok = TRUE;
out:
	if (chip_pub2)
		EC_POINT_free(chip_pub2);
	if (shared)
		EC_POINT_free(shared);
	if (x)
		BN_free(x);
	if (y)
		BN_free(y);
	memset(k, 0, sizeof(k));
	return ok;
}

/* Input data object for a Mutual Authenticate token, 9303-11 Supplement
 * G.1.2.4: 7F49 4F { 06 0A <oid> 86 41 <peer's round-3 ephemeral pubkey> } */
static GByteArray *encode_token_input(const guint8 pub2[EC_PUB_LEN])
{
	GByteArray *inner = g_byte_array_new();
	GByteArray *out = g_byte_array_new();
	guint8 oid_tlv[2] = { 0x06, (guint8) sizeof(pace_oid) };
	guint8 pub_tlv[2] = { 0x86, (guint8) EC_PUB_LEN };
	guint8 outer_hdr[3] = { 0x7F, 0x49, (guint8)(sizeof(oid_tlv) + sizeof(pace_oid) +
	                                            sizeof(pub_tlv) + EC_PUB_LEN) };

	g_byte_array_append(inner, oid_tlv, sizeof(oid_tlv));
	g_byte_array_append(inner, pace_oid, sizeof(pace_oid));
	g_byte_array_append(inner, pub_tlv, sizeof(pub_tlv));
	g_byte_array_append(inner, pub2, EC_PUB_LEN);

	g_byte_array_append(out, outer_hdr, sizeof(outer_hdr));
	g_byte_array_append(out, inner->data, inner->len);
	g_byte_array_free(inner, TRUE);
	return out;
}

static gboolean compute_token(const guint8 ks_mac[PACE_KEY_LEN], const guint8 pub2[EC_PUB_LEN],
                              guint8 token_out[8])
{
	GByteArray *input = encode_token_input(pub2);
	guint8 mac[AES_BLOCK_LEN];
	gboolean ok = aes_cmac(ks_mac, input->data, input->len, mac);

	g_byte_array_free(input, TRUE);
	if (ok)
		memcpy(token_out, mac, 8);
	return ok;
}

GByteArray *pace_build_mutual_auth(PaceExchange *pace)
{
	GByteArray *dad, *apdu;
	guint8 token[8];
	guint8 header[] = { 0x00, 0x86, 0x00, 0x00 };
	guint8 lc, le = 0x00;

	/* T_PCD authenticates to the chip using the chip's own round-3 key */
	if (!compute_token(pace->session.ks_mac, pace->chip_pub2, token))
		return NULL;

	dad = wrap_7c(0x85, token, sizeof(token));
	lc = (guint8) dad->len;

	apdu = g_byte_array_new();
	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, &lc, 1);
	g_byte_array_append(apdu, dad->data, dad->len);
	g_byte_array_append(apdu, &le, 1);
	g_byte_array_free(dad, TRUE);
	return apdu;
}

gboolean pace_verify_mutual_auth_response(PaceExchange *pace, const guint8 *resp, gsize len)
{
	const guint8 *chip_token;
	gsize chip_token_len;
	guint8 expect[8];

	if (!find_in_7c(resp, len, 0x86, &chip_token, &chip_token_len) || chip_token_len != 8)
		return FALSE;

	/* T_PICC authenticates the chip to us using our own round-3 key */
	if (!compute_token(pace->session.ks_mac, pace->my_pub2, expect))
		return FALSE;

	return bytes_equal(expect, chip_token, 8);
}

/* ---- Secure messaging: same DO'87'/'97'/'99'/'8E' TLV shape as
 * bac_sm_protect()/unprotect(), AES instead of 3DES (see pace.h) ---- */

static void ssc_increment(guint8 ssc[PACE_SSC_LEN])
{
	for (int n = PACE_SSC_LEN - 1; n >= 0; n--)
		if (++ssc[n] != 0)
			break;
}

static GByteArray *iso_pad(const guint8 *data, gsize len)
{
	GByteArray *out = g_byte_array_new();
	gsize pad = AES_BLOCK_LEN - (len % AES_BLOCK_LEN);
	guint8 marker = 0x80;

	g_byte_array_append(out, data, len);
	g_byte_array_append(out, &marker, 1);
	for (gsize n = 1; n < pad; n++) {
		guint8 zero = 0x00;
		g_byte_array_append(out, &zero, 1);
	}
	return out;
}

static void append_tlv(GByteArray *out, guint8 tag, const guint8 *data, gsize len)
{
	guint8 hdr[2] = { tag, (guint8) len };

	g_byte_array_append(out, hdr, 2);
	if (len)
		g_byte_array_append(out, data, len);
}

GByteArray *pace_sm_protect(PaceSession *session, guint8 cla, guint8 ins, guint8 p1, guint8 p2,
                            const guint8 *data, gsize data_len, gint le)
{
	guint8 header[4] = { (guint8)(cla | 0x0C), ins, p1, p2 };
	GByteArray *header_padded = iso_pad(header, sizeof(header));
	GByteArray *do87 = NULL, *do97 = NULL;
	GByteArray *m, *n, *apdu;
	guint8 mac[AES_BLOCK_LEN];
	guint8 lc;

	if (le > 255 || data_len > 190) /* keeps do87's short-form length valid */
		return NULL;

	/* SSC must be incremented before use - both the encryption IV and
	 * the MAC's SSC prefix are the SAME (new) value (9303-11 Annex F.5:
	 * "increased every time before a command ... is generated"). */
	ssc_increment(session->ssc);

	if (data && data_len > 0) {
		GByteArray *padded = iso_pad(data, data_len);
		guint8 iv[AES_BLOCK_LEN], *enc = g_malloc(padded->len);
		guint8 pad_indicator = 0x01;
		GByteArray *enc_field;
		gboolean ok;

		ok = aes_ecb_encrypt_block(session->ks_enc, session->ssc, iv) &&
		    aes_cbc(TRUE, session->ks_enc, iv, padded->data, padded->len, enc);
		if (!ok) {
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

	n = g_byte_array_new();
	g_byte_array_append(n, session->ssc, PACE_SSC_LEN);
	g_byte_array_append(n, m->data, m->len);
	g_byte_array_free(m, TRUE);

	{
		guint8 full_mac[AES_BLOCK_LEN];
		gboolean ok = aes_cmac(session->ks_mac, n->data, n->len, full_mac);

		g_byte_array_free(n, TRUE);
		if (!ok) {
			if (do87)
				g_byte_array_free(do87, TRUE);
			if (do97)
				g_byte_array_free(do97, TRUE);
			return NULL;
		}
		memcpy(mac, full_mac, 8);
	}

	lc = (guint8)((do87 ? do87->len : 0) + (do97 ? do97->len : 0) + 2 + 8);

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
	append_tlv(apdu, 0x8E, mac, 8);
	{
		guint8 trailing_le = 0x00;
		g_byte_array_append(apdu, &trailing_le, 1);
	}

	return apdu;
}

gboolean pace_sm_unprotect(PaceSession *session, const guint8 *rapdu, gsize rapdu_len,
                           GByteArray **plaintext_out, guint16 *sw_out)
{
	gsize pos = 0;
	const guint8 *do87 = NULL; gsize do87_len = 0;
	const guint8 *do99 = NULL; gsize do99_len = 0;
	const guint8 *do8e = NULL; gsize do8e_len = 0;
	GByteArray *mac_input;
	guint8 mac[AES_BLOCK_LEN];

	*plaintext_out = NULL;

	if (rapdu_len < 2)
		return FALSE;

	while (pos + 2 <= rapdu_len) {
		guint8 tag = rapdu[pos];
		guint8 clen = rapdu[pos + 1]; /* short-form only - PACE reads never exceed this */

		if (clen >= 0x80 || pos + 2 + clen > rapdu_len)
			return FALSE;

		if (tag == 0x87) { do87 = rapdu + pos; do87_len = 2 + clen; }
		else if (tag == 0x99) { do99 = rapdu + pos; do99_len = 2 + clen; }
		else if (tag == 0x8E) { do8e = rapdu + pos; do8e_len = 2 + clen; }

		pos += 2 + clen;
	}

	if (!do99 || do99_len != 4 || !do8e || do8e_len != 2 + 8)
		return FALSE;

	ssc_increment(session->ssc);
	mac_input = g_byte_array_new();
	g_byte_array_append(mac_input, session->ssc, PACE_SSC_LEN);
	if (do87)
		g_byte_array_append(mac_input, do87, do87_len);
	g_byte_array_append(mac_input, do99, do99_len);

	{
		gboolean mac_ok = aes_cmac(session->ks_mac, mac_input->data, mac_input->len, mac);

		g_byte_array_free(mac_input, TRUE);
		if (!mac_ok)
			return FALSE;
	}

	if (!bytes_equal(mac, do8e + 2, 8))
		return FALSE;

	*sw_out = (guint16)((do99[2] << 8) | do99[3]);

	if (do87) {
		guint8 clen = do87[1];
		const guint8 *enc;
		gsize enc_len;
		guint8 iv[AES_BLOCK_LEN], *dec;
		gsize i;

		if (clen < 1 || do87[2] != 0x01)
			return FALSE;

		enc = do87 + 3;
		enc_len = clen - 1;
		if (enc_len == 0 || enc_len % AES_BLOCK_LEN != 0)
			return FALSE;

		if (!aes_ecb_encrypt_block(session->ks_enc, session->ssc, iv))
			return FALSE;

		dec = g_malloc(enc_len);
		if (!aes_cbc(FALSE, session->ks_enc, iv, enc, enc_len, dec)) {
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
