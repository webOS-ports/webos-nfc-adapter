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

#define AES_BLOCK_LEN		16	/* fixed AES block size - independent of key length */
#define PACE_COORD_LEN_MAX	40	/* brainpoolP320r1 field element size - the widest curve below */
#define PACE_PUB_LEN_MAX	(1 + 2 * PACE_COORD_LEN_MAX)	/* uncompressed point, 0x04 || x || y */
/* TR-03110-3 A.3.3: the nonce s is "a multiple of the block size", not
 * necessarily one block - real AES-256 documents use a 256-bit (2-block)
 * nonce (confirmed against real hardware: a captured GET NONCE response
 * was 32 bytes, not 16). 4 blocks is generous headroom over every
 * documented profile up to AES-256; anything longer is rejected rather
 * than silently truncated or over-allocated for an untrusted chip claim. */
#define PACE_NONCE_LEN_MAX	(4 * AES_BLOCK_LEN)

/* id-PACE-ECDH-GM-AES-CBC-CMAC-{128,256}, BSI TR-03110-3 Table 7 / ICAO
 * 9303 Supplement Appendix G.1.1 - the two PACEInfo variants this file
 * implements (arc suffix 2/4; suffix 3, AES-192, isn't). Only the last
 * byte differs, so oid_len is shared. */
static const guint8 pace_oid_aes128[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02 };
static const guint8 pace_oid_aes256[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04 };

/* id-PACE = 0.4.0.127.0.7.2.2.4 - every PACEInfo OID (any mapping, any
 * cipher) starts with this; used to pick SecurityInfo entries worth
 * looking at out of EF.CardAccess (which also lists unrelated protocols
 * like Chip/Terminal Authentication). */
static const guint8 id_pace_prefix[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04 };

/* 0 if oid isn't one of the variants above - the one place that decides
 * which OIDs this file accepts; pace_oid_supported() and
 * pace_exchange_new() both go through this instead of duplicating the
 * comparison. */
static gsize pace_key_len_for_oid(const guint8 *oid, gsize oid_len)
{
	if (oid_len == sizeof(pace_oid_aes128) && memcmp(oid, pace_oid_aes128, oid_len) == 0)
		return 16;
	if (oid_len == sizeof(pace_oid_aes256) && memcmp(oid, pace_oid_aes256, oid_len) == 0)
		return 32;
	return 0;
}

gboolean pace_oid_supported(const guint8 *oid, gsize oid_len)
{
	return pace_key_len_for_oid(oid, oid_len) != 0;
}

int pace_ec_curve_for_parameter_id(gint parameter_id)
{
	switch (parameter_id) {
	case 12: return NID_X9_62_prime256v1;	/* NIST P-256 / secp256r1 */
	case 13: return NID_brainpoolP256r1;
	case 14: return NID_brainpoolP320r1;
	default: return 0;	/* DH IDs, or an EC curve nothing here has been tried against */
	}
}

/* ---- EF.CardAccess = DER SET OF SecurityInfo (SEQUENCE { OID, INTEGER
 * version, INTEGER parameterId OPTIONAL }) - reuses bac_ber_tlv_header()
 * for the TLV walk, same as this file's own APDU parsing. ---- */

gsize pace_parse_card_access(const guint8 *data, gsize len, PaceInfoEntry *entries,
                             gsize max_entries)
{
	gsize outer_header, outer_content, pos, end, count = 0;

	if (len < 2 || data[0] != 0x31 ||
	    !bac_ber_tlv_header(data, len, &outer_header, &outer_content) ||
	    outer_header + outer_content > len)
		return 0;

	pos = outer_header;
	end = outer_header + outer_content;

	while (pos < end && count < max_entries) {
		gsize seq_header, seq_content, seq_len, p;
		const guint8 *seq = data + pos;

		if (data[pos] != 0x30 ||
		    !bac_ber_tlv_header(seq, end - pos, &seq_header, &seq_content))
			break;

		seq_len = seq_header + seq_content;
		if (pos + seq_len > end)
			break;

		p = seq_header;
		if (p < seq_len && seq[p] == 0x06) {
			gsize oid_hdr, oid_content;

			if (bac_ber_tlv_header(seq + p, seq_len - p, &oid_hdr, &oid_content) &&
			    oid_content > 0 && oid_content <= sizeof(entries[0].oid) &&
			    oid_content >= sizeof(id_pace_prefix) &&
			    memcmp(seq + p + oid_hdr, id_pace_prefix, sizeof(id_pace_prefix)) == 0) {
				PaceInfoEntry *e = &entries[count];

				memcpy(e->oid, seq + p + oid_hdr, oid_content);
				e->oid_len = oid_content;
				e->parameter_id = -1;
				p += oid_hdr + oid_content;

				/* INTEGER version (must be 2, not checked - unsupported
				 * versions still name a real OID/parameterId worth
				 * reporting in a rejection message) */
				if (p < seq_len && seq[p] == 0x02) {
					gsize vh, vc;

					if (bac_ber_tlv_header(seq + p, seq_len - p, &vh, &vc))
						p += vh + vc;
				}

				/* optional trailing INTEGER parameterId */
				if (p < seq_len && seq[p] == 0x02) {
					gsize ih, ic;

					if (bac_ber_tlv_header(seq + p, seq_len - p, &ih, &ic) &&
					    ic >= 1 && ic <= 4) {
						gint val = 0;
						gsize i;

						for (i = 0; i < ic; i++)
							val = (val << 8) | seq[p + ih + i];
						e->parameter_id = val;
					}
				}
				count++;
			}
		}
		pos += seq_len;
	}
	return count;
}

struct PaceExchange {
	guint8 oid[16];
	gsize oid_len;
	gsize key_len;		/* 16 (AES-128) or 32 (AES-256) - from the negotiated oid */

	guint8 kpi[PACE_KEY_LEN_MAX];
	guint8 nonce_s[PACE_NONCE_LEN_MAX];
	gsize nonce_len;	/* chip-chosen; a multiple of AES_BLOCK_LEN (see PACE_NONCE_LEN_MAX) */

	gsize coord_len;	/* EC field element size for `group` (and group2): 32 or 40 */
	gsize pub_len;		/* 1 + 2*coord_len */

	BN_CTX *ctx;
	EC_GROUP *group;	/* the negotiated curve (see pace_ec_curve_for_parameter_id()) */
	BIGNUM *priv1;		/* round 2: our ephemeral mapping key */
	EC_GROUP *group2;	/* round 2 result: same curve, generator G~ */
	BIGNUM *priv2;		/* round 3: our ephemeral key-agreement key */
	guint8 my_pub2[PACE_PUB_LEN_MAX];
	guint8 chip_pub2[PACE_PUB_LEN_MAX];

	PaceSession session;	/* usable once round 3 completes */
};

/* ---- KDF: TR-03110 A.2.3/A.2.3.2 - keydata = H(K || r || c) (r is empty
 * for PACE; that's a Chip Authentication v2 thing), no DES parity (that's
 * a 3DES/BAC-specific extra step - see bac.c's kdf(), which this is not).
 * H and the truncation both depend on the target key length: 128-bit AES
 * keys use SHA-1 and the first 16 bytes; 192/256-bit keys use SHA-256, and
 * for 256-bit the full digest *is* the key (32 bytes in, 32 out - nothing
 * to truncate). K is whatever-length here (a CAN string or a 20-byte MRZ
 * digest), unlike BAC's always-16-byte kseed, so this can't just call
 * bac.c's version. ---- */
static void pace_kdf(const guint8 *k, gsize k_len, guint32 c, gsize key_len,
                     guint8 out[PACE_KEY_LEN_MAX])
{
	guint8 *d = g_malloc(k_len + 4);

	memcpy(d, k, k_len);
	d[k_len + 0] = (guint8)(c >> 24);
	d[k_len + 1] = (guint8)(c >> 16);
	d[k_len + 2] = (guint8)(c >> 8);
	d[k_len + 3] = (guint8)(c);

	if (key_len == 16) {
		guint8 digest[SHA_DIGEST_LENGTH];

		SHA1(d, k_len + 4, digest);
		memcpy(out, digest, 16);
	} else {
		guint8 digest[SHA256_DIGEST_LENGTH];

		SHA256(d, k_len + 4, digest);
		memcpy(out, digest, key_len <= sizeof(digest) ? key_len : sizeof(digest));
	}
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
 * block-aligned) and truncated AES-CMAC, the two primitives PACE's secure
 * messaging and Mutual Authenticate steps both need. Every one of these
 * takes key_len (16 or 32) and picks AES-128 vs AES-256 - the block size
 * (and so the IV/output size) is unaffected, only the key/cipher is. ---- */

static const EVP_CIPHER *aes_cbc_cipher(gsize key_len)
{
	return key_len == 32 ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
}

static const EVP_CIPHER *aes_ecb_cipher(gsize key_len)
{
	return key_len == 32 ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
}

static const char *aes_cmac_cipher_name(gsize key_len)
{
	return key_len == 32 ? "AES-256-CBC" : "AES-128-CBC";
}

static gboolean aes_cbc(gboolean encrypt, const guint8 *key, gsize key_len,
                        const guint8 iv[AES_BLOCK_LEN], const guint8 *in, gsize len, guint8 *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int outlen1 = 0, outlen2 = 0;
	gboolean ok;

	if (!ctx)
		return FALSE;

	ok = EVP_CipherInit_ex(ctx, aes_cbc_cipher(key_len), NULL, key, iv, encrypt) &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) &&
	    EVP_CipherUpdate(ctx, out, &outlen1, in, (int) len) &&
	    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);

	EVP_CIPHER_CTX_free(ctx);
	return ok && (gsize)(outlen1 + outlen2) == len;
}

/* AES-ECB single block - used only to compute the SM encryption IV,
 * E(KSenc, SSC) (9303-11 Annex F.4.2.1), not for bulk data. */
static gboolean aes_ecb_encrypt_block(const guint8 *key, gsize key_len,
                                      const guint8 in[AES_BLOCK_LEN], guint8 out[AES_BLOCK_LEN])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int outlen1 = 0, outlen2 = 0;
	gboolean ok;

	if (!ctx)
		return FALSE;

	ok = EVP_CipherInit_ex(ctx, aes_ecb_cipher(key_len), NULL, key, NULL, 1) &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) &&
	    EVP_CipherUpdate(ctx, out, &outlen1, in, AES_BLOCK_LEN) &&
	    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);

	EVP_CIPHER_CTX_free(ctx);
	return ok && outlen1 + outlen2 == AES_BLOCK_LEN;
}

/* Full (16-byte) AES-CMAC - callers needing the 8-byte authentication
 * token truncate the result themselves (9303-11 Annex A.2.4/F.4.2.2 both
 * truncate, but to different things: a token vs a MAC datagram prefix).
 * The MAC's own output is always one block (128 bits) regardless of key
 * length - only the key/cipher passed to EVP_Q_mac changes. */
static gboolean aes_cmac(const guint8 *key, gsize key_len, const guint8 *data, gsize len,
                         guint8 out[AES_BLOCK_LEN])
{
	size_t outlen = 0;

	return EVP_Q_mac(NULL, "CMAC", NULL, aes_cmac_cipher_name(key_len), NULL, key, key_len,
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

GByteArray *pace_build_mse_set_at(const guint8 *oid, gsize oid_len, gboolean use_can)
{
	GByteArray *apdu = g_byte_array_new();
	guint8 header[] = { 0x00, 0x22, 0xC1, 0xA4 };
	guint8 oid_tlv[2] = { 0x80, (guint8) oid_len };
	guint8 pwd_tlv[3] = { 0x83, 0x01, (guint8)(use_can ? 0x02 : 0x01) };
	guint8 lc = (guint8)(sizeof(oid_tlv) + oid_len + sizeof(pwd_tlv));

	g_byte_array_append(apdu, header, sizeof(header));
	g_byte_array_append(apdu, &lc, 1);
	g_byte_array_append(apdu, oid_tlv, sizeof(oid_tlv));
	g_byte_array_append(apdu, oid, oid_len);
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

PaceExchange *pace_exchange_new(const GByteArray *k, int curve_nid, const guint8 *oid,
                                gsize oid_len)
{
	PaceExchange *pace;
	EC_GROUP *group;
	BN_CTX *ctx;
	gsize key_len = pace_key_len_for_oid(oid, oid_len);
	gint degree;
	gsize coord_len;

	if (curve_nid == 0 || key_len == 0 || oid_len > sizeof(pace->oid))
		return NULL;

	group = EC_GROUP_new_by_curve_name(curve_nid);
	ctx = BN_CTX_new();

	if (!group || !ctx) {
		if (group)
			EC_GROUP_free(group);
		if (ctx)
			BN_CTX_free(ctx);
		return NULL;
	}

	degree = EC_GROUP_get_degree(group);
	coord_len = degree > 0 ? (gsize)(degree + 7) / 8 : 0;
	if (coord_len == 0 || coord_len > PACE_COORD_LEN_MAX) {
		EC_GROUP_free(group);
		BN_CTX_free(ctx);
		return NULL;
	}

	pace = g_new0(PaceExchange, 1);
	pace->group = group;
	pace->ctx = ctx;
	pace->key_len = key_len;
	pace->coord_len = coord_len;
	pace->pub_len = 1 + 2 * coord_len;
	memcpy(pace->oid, oid, oid_len);
	pace->oid_len = oid_len;
	pace_kdf(k->data, k->len, 3, key_len, pace->kpi);
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

	if (!find_in_7c(resp, len, 0x80, &z, &z_len))
		return FALSE;
	if (z_len == 0 || z_len % AES_BLOCK_LEN != 0 || z_len > PACE_NONCE_LEN_MAX)
		return FALSE;

	if (!aes_cbc(FALSE, pace->kpi, pace->key_len, (guint8[AES_BLOCK_LEN]) { 0 }, z, z_len,
	            pace->nonce_s))
		return FALSE;
	pace->nonce_len = z_len;
	return TRUE;
}

/* Serializes an EC_POINT as an uncompressed octet string, 0x04 || x || y.
 * pub_len is the curve's own (1 + 2*coord_len) - callers pass pace->pub_len. */
static gboolean point_to_bytes(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx,
                               guint8 *out, gsize pub_len)
{
	return EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, out, pub_len,
	                          ctx) == pub_len;
}

static EC_POINT *point_from_bytes(const EC_GROUP *group, const guint8 *data, gsize len,
                                  BN_CTX *ctx, gsize expect_pub_len)
{
	EC_POINT *point;

	if (len != expect_pub_len || data[0] != 0x04)
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
	guint8 pub1_bytes[PACE_PUB_LEN_MAX];
	GByteArray *apdu;

	pace->priv1 = random_scalar(EC_GROUP_get0_order(pace->group));
	if (!pace->priv1)
		return NULL;

	pub1 = EC_POINT_new(pace->group);
	if (!pub1)
		return NULL;
	if (!EC_POINT_mul(pace->group, pub1, pace->priv1, NULL, NULL, pace->ctx) ||
	   !point_to_bytes(pace->group, pub1, pace->ctx, pub1_bytes, pace->pub_len)) {
		EC_POINT_free(pub1);
		return NULL;
	}
	EC_POINT_free(pub1);

	apdu = build_ga(0x81, pub1_bytes, pace->pub_len);
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

	chip_pub1 = point_from_bytes(pace->group, chip_pub1_bytes, chip_pub1_len, pace->ctx,
	                             pace->pub_len);
	h = EC_POINT_new(pace->group);
	sg = EC_POINT_new(pace->group);
	gtilde = EC_POINT_new(pace->group);
	s = BN_bin2bn(pace->nonce_s, pace->nonce_len, NULL);
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
	    point_to_bytes(pace->group2, pub2, pace->ctx, pace->my_pub2, pace->pub_len);
	EC_POINT_free(pub2);
	if (!ok)
		return NULL;

	return build_ga(0x83, pace->my_pub2, pace->pub_len);
}

gboolean pace_process_key_agreement_response(PaceExchange *pace, const guint8 *resp, gsize len,
                                             PaceSession *session_out)
{
	const guint8 *chip_pub2_bytes;
	gsize chip_pub2_len;
	EC_POINT *chip_pub2 = NULL, *shared = NULL;
	BIGNUM *x = NULL, *y = NULL;
	guint8 k[PACE_COORD_LEN_MAX];
	gboolean ok = FALSE;

	if (!find_in_7c(resp, len, 0x84, &chip_pub2_bytes, &chip_pub2_len))
		return FALSE;
	if (chip_pub2_len != pace->pub_len)
		return FALSE;
	memcpy(pace->chip_pub2, chip_pub2_bytes, chip_pub2_len);

	chip_pub2 = point_from_bytes(pace->group2, chip_pub2_bytes, chip_pub2_len, pace->ctx,
	                             pace->pub_len);
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
	if (BN_bn2binpad(x, k, pace->coord_len) != (int) pace->coord_len)
		goto out;

	pace_kdf(k, pace->coord_len, 1, pace->key_len, pace->session.ks_enc);
	pace_kdf(k, pace->coord_len, 2, pace->key_len, pace->session.ks_mac);
	pace->session.key_len = pace->key_len;
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
 * G.1.2.4: 7F49 4F { 06 0A <oid> 86 41 <peer's round-3 ephemeral pubkey> }
 * - the OID embedded here MUST be the one actually negotiated (pace->oid),
 * not a fixed constant: with two supported OIDs now, whichever one wasn't
 * chosen would make the token computable but wrong. */
static GByteArray *encode_token_input(const PaceExchange *pace, const guint8 *pub2)
{
	GByteArray *inner = g_byte_array_new();
	GByteArray *out = g_byte_array_new();
	guint8 oid_tlv[2] = { 0x06, (guint8) pace->oid_len };
	guint8 pub_tlv[2] = { 0x86, (guint8) pace->pub_len };
	guint8 outer_hdr[3] = { 0x7F, 0x49, (guint8)(sizeof(oid_tlv) + pace->oid_len +
	                                            sizeof(pub_tlv) + pace->pub_len) };

	g_byte_array_append(inner, oid_tlv, sizeof(oid_tlv));
	g_byte_array_append(inner, pace->oid, pace->oid_len);
	g_byte_array_append(inner, pub_tlv, sizeof(pub_tlv));
	g_byte_array_append(inner, pub2, pace->pub_len);

	g_byte_array_append(out, outer_hdr, sizeof(outer_hdr));
	g_byte_array_append(out, inner->data, inner->len);
	g_byte_array_free(inner, TRUE);
	return out;
}

static gboolean compute_token(const PaceExchange *pace, const guint8 *pub2, guint8 token_out[8])
{
	GByteArray *input = encode_token_input(pace, pub2);
	guint8 mac[AES_BLOCK_LEN];
	gboolean ok = aes_cmac(pace->session.ks_mac, pace->key_len, input->data, input->len, mac);

	g_byte_array_free(input, TRUE);
	if (ok)
		memcpy(token_out, mac, 8);
	return ok;
}

GByteArray *pace_build_mutual_auth(const PaceExchange *pace)
{
	GByteArray *dad, *apdu;
	guint8 token[8];
	guint8 header[] = { 0x00, 0x86, 0x00, 0x00 };
	guint8 lc, le = 0x00;

	/* T_PCD authenticates to the chip using the chip's own round-3 key */
	if (!compute_token(pace, pace->chip_pub2, token))
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

gboolean pace_verify_mutual_auth_response(const PaceExchange *pace, const guint8 *resp, gsize len)
{
	const guint8 *chip_token;
	gsize chip_token_len;
	guint8 expect[8];

	if (!find_in_7c(resp, len, 0x86, &chip_token, &chip_token_len) || chip_token_len != 8)
		return FALSE;

	/* T_PICC authenticates the chip to us using our own round-3 key */
	if (!compute_token(pace, pace->my_pub2, expect))
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

		ok = aes_ecb_encrypt_block(session->ks_enc, session->key_len, session->ssc, iv) &&
		    aes_cbc(TRUE, session->ks_enc, session->key_len, iv, padded->data, padded->len, enc);
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
		/* 9303-11 9.8.1: "Padding is always performed by the secure
		 * messaging layer, therefore the underlying [CMAC] need not
		 * perform any internal padding" - i.e. pad N ourselves so it's
		 * already block-aligned, so CMAC's own length-based K1/K2
		 * subkey choice lands on K1 (the "already aligned" branch) the
		 * same way the spec's padded construction intends, instead of
		 * silently taking the K2/auto-pad branch on our unpadded N -
		 * same bytes appended, different (wrong) subkey, wrong MAC. */
		GByteArray *n_padded = iso_pad(n->data, n->len);
		guint8 full_mac[AES_BLOCK_LEN];
		gboolean ok = aes_cmac(session->ks_mac, session->key_len, n_padded->data,
		                       n_padded->len, full_mac);

		g_byte_array_free(n_padded, TRUE);
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
		gsize hlen, clen;

		/* BER length, not short-form-only - DO'87' for anything past a
		 * small DG1-sized read (e.g. DG2's photo) needs long form. */
		if (!bac_ber_tlv_header(rapdu + pos, rapdu_len - pos, &hlen, &clen))
			return FALSE;
		if (pos + hlen + clen > rapdu_len)
			return FALSE;

		if (tag == 0x87) { do87 = rapdu + pos; do87_len = hlen + clen; }
		else if (tag == 0x99) { do99 = rapdu + pos; do99_len = hlen + clen; }
		else if (tag == 0x8E) { do8e = rapdu + pos; do8e_len = hlen + clen; }

		pos += hlen + clen;
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
		/* Same pre-padding as pace_sm_protect() - see the comment there. */
		GByteArray *mac_input_padded = iso_pad(mac_input->data, mac_input->len);
		gboolean mac_ok = aes_cmac(session->ks_mac, session->key_len, mac_input_padded->data,
		                          mac_input_padded->len, mac);

		g_byte_array_free(mac_input_padded, TRUE);
		g_byte_array_free(mac_input, TRUE);
		if (!mac_ok)
			return FALSE;
	}

	if (!bytes_equal(mac, do8e + 2, 8))
		return FALSE;

	*sw_out = (guint16)((do99[2] << 8) | do99[3]);

	if (do87) {
		gsize hlen, clen;
		const guint8 *enc;
		gsize enc_len;
		guint8 iv[AES_BLOCK_LEN], *dec;
		gsize i;

		if (!bac_ber_tlv_header(do87, do87_len, &hlen, &clen) || clen < 1)
			return FALSE;
		if (do87[hlen] != 0x01)
			return FALSE;

		enc = do87 + hlen + 1;
		enc_len = clen - 1;
		if (enc_len == 0 || enc_len % AES_BLOCK_LEN != 0)
			return FALSE;

		if (!aes_ecb_encrypt_block(session->ks_enc, session->key_len, session->ssc, iv))
			return FALSE;

		dec = g_malloc(enc_len);
		if (!aes_cbc(FALSE, session->ks_enc, session->key_len, iv, enc, enc_len, dec)) {
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
