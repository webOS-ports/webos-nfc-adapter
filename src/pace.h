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

#ifndef PACE_H_
#define PACE_H_

#include <glib.h>

/*
 * ICAO Doc 9303 Part 11 / BSI TR-03110 PACE (Password Authenticated
 * Connection Establishment): where BAC just derives static keys from the
 * MRZ, PACE runs an ephemeral ECDH key agreement (chip-generated nonce,
 * generic mapping to a per-session curve generator, then a second ECDH on
 * that mapped curve) so the session keys are never derivable from the
 * password alone - the reason chips that support it use it instead of
 * BAC. Implements ECDH generic mapping with AES-128 or AES-256 session
 * keys (id-PACE-ECDH-GM-AES-CBC-CMAC-128/256). The AES-128 path is
 * verified against the worked example in ICAO 9303 Supplement, Appendix G
 * (brainpoolP256r1); no official worked example exists yet for AES-256 -
 * see pace_kdf()/aes_cbc()/aes_cmac() for how that path is verified
 * instead (NIST primitive vectors, real hardware).
 *
 * The chip's own EF.CardAccess (read unauthenticated, before MSE:Set AT -
 * see pace_parse_card_access()) says which PACE variant and domain
 * parameters it actually wants; real documents vary (NIST P-256 is just
 * as common as brainpoolP256r1, and BSI TR-03110-3 Table 4's 320-bit
 * BrainpoolP320r1, parameter ID 14, shows up in the wild too - it's what
 * this build was extended for). pace_ec_curve_for_parameter_id() derives
 * the field width from the curve itself (EC_GROUP_get_degree()) rather
 * than hardcoding it per ID, so any EC curve OpenSSL knows about "just
 * works" as long as its field fits PACE_COORD_LEN_MAX. AES-192
 * (id-PACE-*-192, TR-03110-3 Table 7 arc suffix 3) and Integrated/Chip-
 * Authentication Mapping remain unsupported - a document advertising them
 * gets a clean, honest rejection naming exactly what it asked for.
 */

#define PACE_KEY_LEN_MAX	32	/* AES-256 */
#define PACE_SSC_LEN		16	/* AES block size - fixed regardless of key length */

typedef struct {
	guint8 ks_enc[PACE_KEY_LEN_MAX];
	guint8 ks_mac[PACE_KEY_LEN_MAX];
	guint8 ssc[PACE_SSC_LEN];
	gsize key_len;		/* 16 (AES-128) or 32 (AES-256) - which of the above is live */
} PaceSession;

typedef struct PaceExchange PaceExchange;

/* K per TR-03110 Table 5 "Password Encoding": the CAN's own ISO 8859-1
 * digit characters, NOT hashed (unlike MRZ). Returns NULL if can is empty. */
GByteArray *pace_derive_k_can(const char *can);

/* K for the MRZ password: the full 20-byte SHA-1 digest bac_mrz_sha1()
 * computes (PACE uses it whole; BAC, uniquely, truncates it to 16 bytes
 * before its own KDF - see bac_mrz_sha1()'s comment in bac.h). */
GByteArray *pace_derive_k_mrz(const char *document_number, const char *date_of_birth,
                              const char *date_of_expiry);

/* One PACEInfo entry found in EF.CardAccess: its protocol OID and,
 * for standardized EC domain parameters, the parameterId (TR-03110
 * Table 6) - -1 if absent (explicit/proprietary domain parameters,
 * which this implementation doesn't support). */
typedef struct {
	guint8 oid[16];
	gsize oid_len;
	gint parameter_id;
} PaceInfoEntry;

/* Parses EF.CardAccess = DER SET OF SecurityInfo (ICAO 9303-11 4.1 /
 * TR-03110 3.2.1), returning every PACEInfo entry found (SecurityInfos
 * whose OID falls under id-PACE), up to max_entries. A malformed file
 * or one with no PACEInfo just yields 0 - EF.CardAccess isn't itself
 * authenticated, so that's "nothing usable", not a hard parse error. */
gsize pace_parse_card_access(const guint8 *data, gsize len, PaceInfoEntry *entries,
                             gsize max_entries);

/* True if oid is a PACE variant this build actually implements
 * (id-PACE-ECDH-GM-AES-CBC-CMAC-128 or -256). */
gboolean pace_oid_supported(const guint8 *oid, gsize oid_len);

/* Maps a standardized EC parameterId (TR-03110 Table 4, IDs 8-18) to an
 * OpenSSL curve NID - only the ones whose field element fits
 * PACE_COORD_LEN_MAX (currently every one of them does: the largest
 * listed, secp521r1, doesn't - see pace_exchange_new()). 0 for anything
 * else, including the DH (non-EC) IDs 0-2. */
int pace_ec_curve_for_parameter_id(gint parameter_id);

/*
 * Starts a PACE exchange: derives Kpi = KDF(K,3) (TR-03110 A.2.3.2) from
 * the password encoding k, on the given OpenSSL curve NID (from
 * pace_ec_curve_for_parameter_id()), using the AES key length that oid
 * (one of pace_oid_supported()'s variants) selects. oid is copied - the
 * caller doesn't need to keep it (or k) alive past this call. Returns NULL
 * on an OpenSSL EC setup failure, an unsupported curve_nid/oid, or a curve
 * whose field is wider than PACE_COORD_LEN_MAX.
 */
PaceExchange *pace_exchange_new(const GByteArray *k, int curve_nid, const guint8 *oid,
                                gsize oid_len);
void pace_exchange_free(PaceExchange *pace);

/* MSE:Set AT: 00 22 C1 A4, selecting the given PACEInfo protocol OID
 * (see pace_oid_supported()) and either CAN (use_can) or MRZ as the
 * password reference. */
GByteArray *pace_build_mse_set_at(const guint8 *oid, gsize oid_len, gboolean use_can);

/* Round 1, Encrypted Nonce: empty General Authenticate, asks the chip to
 * return its nonce s encrypted under Kpi. */
GByteArray *pace_build_get_nonce(void);
gboolean pace_process_nonce_response(PaceExchange *pace, const guint8 *resp, gsize len);

/* Round 2, Map Nonce: exchanges ephemeral "mapping" EC keys, then derives
 * the session-specific mapped generator G~ = s*G + ECDH(mapping keys). */
GByteArray *pace_build_map_nonce(PaceExchange *pace);
gboolean pace_process_map_nonce_response(PaceExchange *pace, const guint8 *resp, gsize len);

/* Round 3, Perform Key Agreement: a second ephemeral ECDH, this time on
 * the curve with generator G~. Only the shared point's x-coordinate feeds
 * the KDF (TR-03110 A.2.3, note on ECKA), producing KS_enc/KS_mac. */
GByteArray *pace_build_key_agreement(PaceExchange *pace);
gboolean pace_process_key_agreement_response(PaceExchange *pace, const guint8 *resp, gsize len,
                                             PaceSession *session_out);

/* Round 4, Mutual Authenticate: each side proves it derived the same
 * KS_mac by sending an AES-CMAC (truncated to 8 bytes) over the other
 * side's round-3 ephemeral public key. */
GByteArray *pace_build_mutual_auth(const PaceExchange *pace);
gboolean pace_verify_mutual_auth_response(const PaceExchange *pace, const guint8 *resp, gsize len);

/*
 * Secure messaging after PACE: same DO'87'/'97'/'99'/'8E' TLV wrapping as
 * bac_sm_protect()/bac_sm_unprotect() (9303-11 Annex F), but AES-CBC/
 * AES-CMAC (128 or 256-bit, per session->key_len) instead of 3DES/
 * retail-MAC, a 16-byte (not 8-byte) IV/SSC, and an encryption IV of
 * E(KSenc, SSC) rather than an all-zero IV - different enough from BAC's
 * session crypto that sharing bac.c's functions isn't an option. SSC
 * starts at all-zero (TR-03110 F.5) and is expected to already be so in
 * *session on the first call after pace_process_key_agreement_response()
 * (which also sets key_len - callers don't set it themselves). The MAC
 * input is ISO-padded before hashing (9303-11 9.8.1: "padding is always
 * performed by the secure messaging layer" - real hardware confirmed this
 * the hard way: without it, AES-CMAC's own internal padding picks the
 * wrong subkey and every protected exchange gets rejected by the chip).
 */
GByteArray *pace_sm_protect(PaceSession *session, guint8 cla, guint8 ins, guint8 p1, guint8 p2,
                            const guint8 *data, gsize data_len, gint le);
gboolean pace_sm_unprotect(PaceSession *session, const guint8 *rapdu, gsize rapdu_len,
                           GByteArray **plaintext_out, guint16 *sw_out);

#endif

// vim:ts=4:sw=4:noexpandtab
