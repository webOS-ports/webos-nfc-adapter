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
 * BAC. Implements ECDH generic mapping with AES-128 session keys
 * (id-PACE-ECDH-GM-AES-CBC-CMAC-128) on the standardized brainpoolP256r1
 * domain parameters, since that's what this implementation is verified
 * against (see the worked example in ICAO 9303 Supplement, Appendix G).
 *
 * Scope note: a chip's actual PACEInfo (in EF.CardAccess) can name a
 * different curve or a different PACE variant entirely - this
 * implementation does not read/parse EF.CardAccess and always asserts the
 * brainpoolP256r1/AES-128/CAM-GM combination in MSE:Set AT. If the chip
 * needs something else, MSE:Set AT or the round-1 GET NONCE step will
 * simply fail (see pace_build_mse_set_at()'s comment) - a clean, honest
 * failure, not a silent wrong-parameter attempt.
 */

#define PACE_KEY_LEN	16	/* AES-128 */
#define PACE_SSC_LEN	16	/* AES block size */

typedef struct {
	guint8 ks_enc[PACE_KEY_LEN];
	guint8 ks_mac[PACE_KEY_LEN];
	guint8 ssc[PACE_SSC_LEN];
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

/*
 * Starts a PACE exchange: derives Kpi = KDF(K,3) (TR-03110 A.2.3.2) from
 * the password encoding k. Caller keeps ownership of k and can free it
 * right after this call. Returns NULL on an OpenSSL EC setup failure.
 */
PaceExchange *pace_exchange_new(const GByteArray *k);
void pace_exchange_free(PaceExchange *pace);

/* MSE:Set AT: 00 22 C1 A4, selecting id-PACE-ECDH-GM-AES-CBC-CMAC-128 and
 * either CAN (use_can) or MRZ as the password reference. */
GByteArray *pace_build_mse_set_at(gboolean use_can);

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
GByteArray *pace_build_mutual_auth(PaceExchange *pace);
gboolean pace_verify_mutual_auth_response(PaceExchange *pace, const guint8 *resp, gsize len);

/*
 * Secure messaging after PACE: same DO'87'/'97'/'99'/'8E' TLV wrapping as
 * bac_sm_protect()/bac_sm_unprotect() (9303-11 Annex F), but AES-CBC/
 * AES-CMAC-128 instead of 3DES/retail-MAC, a 16-byte (not 8-byte) IV/SSC,
 * and an encryption IV of E(KSenc, SSC) rather than an all-zero IV -
 * different enough from BAC's session crypto that sharing bac.c's
 * functions isn't an option. SSC starts at all-zero (TR-03110 F.5) and is
 * expected to already be so in *session on the first call after
 * pace_process_key_agreement_response().
 */
GByteArray *pace_sm_protect(PaceSession *session, guint8 cla, guint8 ins, guint8 p1, guint8 p2,
                            const guint8 *data, gsize data_len, gint le);
gboolean pace_sm_unprotect(PaceSession *session, const guint8 *rapdu, gsize rapdu_len,
                           GByteArray **plaintext_out, guint16 *sw_out);

#endif

// vim:ts=4:sw=4:noexpandtab
