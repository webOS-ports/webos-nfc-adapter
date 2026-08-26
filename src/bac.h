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

#ifndef BAC_H_
#define BAC_H_

#include <glib.h>
#include <openssl/sha.h>

/*
 * ICAO Doc 9303 Part 11 Basic Access Control: derive the document's own
 * chip-access keys from data printed on the document itself (MRZ), run the
 * GET CHALLENGE / MUTUAL AUTHENTICATE handshake, then read EF.DG1 (the MRZ
 * copy stored on the chip) under secure messaging as proof the handshake
 * worked. Only usable by whoever already holds the physical document and
 * can read its MRZ - that's the whole point of BAC.
 */

#define BAC_KEY_LEN	16
#define BAC_SSC_LEN	8

typedef struct {
	guint8 kenc[BAC_KEY_LEN];
	guint8 kmac[BAC_KEY_LEN];
} BacStaticKeys;

typedef struct {
	guint8 rnd_ifd[8];
	guint8 k_ifd[BAC_KEY_LEN];
} BacChallenge;

typedef struct {
	guint8 ks_enc[BAC_KEY_LEN];
	guint8 ks_mac[BAC_KEY_LEN];
	guint8 ssc[BAC_SSC_LEN];
} BacSession;

/*
 * Derives KEnc/KMAC from the document number, date of birth and date of
 * expiry as printed in the MRZ (YYMMDD for the dates; check digits are
 * computed here, the caller passes the raw values). Returns FALSE if any
 * field is empty or contains a character invalid in an MRZ.
 */
gboolean bac_derive_static_keys(const char *document_number, const char *date_of_birth,
                                const char *date_of_expiry, BacStaticKeys *keys_out);

/*
 * SHA-1(document number || its check digit || DOB || its check digit ||
 * expiry || its check digit) - the "MRZ information" digest 9303-9's PACE
 * password encoding (Table 5) and BAC's key seed (9.7.1) both build from.
 * BAC then truncates this to 16 bytes itself; PACE (see pace.c) uses the
 * full 20-byte digest as-is. Exported so pace.c doesn't duplicate this.
 */
gboolean bac_mrz_sha1(const char *document_number, const char *date_of_birth,
                      const char *date_of_expiry, guint8 out[SHA_DIGEST_LENGTH]);

/* SELECT the eMRTD application (AID A0000002471001) */
GByteArray *bac_build_select_aid(void);

/* GET CHALLENGE: ask the chip for its 8-byte RND.ICC */
GByteArray *bac_build_get_challenge(void);

/*
 * Builds MUTUAL AUTHENTICATE from the chip's RND.ICC (8 bytes). Generates
 * RND.IFD/K.IFD internally (cryptographically random) and returns them via
 * *challenge_out - the caller must pass the same struct to
 * bac_process_mutual_authenticate_response() once the reply comes back.
 */
GByteArray *bac_build_mutual_authenticate(const BacStaticKeys *keys, const guint8 rnd_icc[8],
                                          BacChallenge *challenge_out);

/*
 * Verifies the MUTUAL AUTHENTICATE response (40 bytes: encrypted data +
 * MAC) and, only if both the MAC and the chip's echoed-back RND.ICC/RND.IFD
 * check out, derives the session keys and initial send sequence counter.
 * Returns FALSE on any verification failure - the chip either doesn't
 * share the key derived from the MRZ (wrong data, or PACE-only document)
 * or the response was tampered with; *session_out is left untouched.
 */
gboolean bac_process_mutual_authenticate_response(const BacStaticKeys *keys,
                                                  const BacChallenge *challenge,
                                                  const guint8 rnd_icc[8],
                                                  const guint8 *response, gsize response_len,
                                                  BacSession *session_out);

/*
 * Wraps a plain APDU (class byte's SM bits get set here - pass the
 * unprotected CLA) as ISO 7816-4 secure messaging per 9303-11 9.8.
 * data/data_len may be NULL/0 (e.g. READ BINARY has no command data).
 * le < 0 means "no Le byte" (not used by anything BAC needs to send).
 * Advances session->ssc. Returns NULL if le is out of single-byte range.
 */
GByteArray *bac_sm_protect(BacSession *session, guint8 cla, guint8 ins, guint8 p1, guint8 p2,
                           const guint8 *data, gsize data_len, gint le);

/*
 * Unwraps a protected response APDU. Always advances session->ssc and
 * checks the response MAC (DO'8E') - returns FALSE on a MAC mismatch
 * without decrypting anything, since the response can no longer be trusted
 * at that point. On TRUE, *sw_out is the status word and *plaintext_out
 * (if the response carried a DO'87') is the decrypted, unpadded data - the
 * caller owns it. *plaintext_out is set to NULL when there was no data.
 */
gboolean bac_sm_unprotect(BacSession *session, const guint8 *rapdu, gsize rapdu_len,
                          GByteArray **plaintext_out, guint16 *sw_out);

/*
 * Parses an EF.DG1 file (tag '61' containing tag '5F1F', the MRZ text) and
 * returns the MRZ as a plain string. Returns NULL if the TLV structure
 * doesn't look like DG1.
 */
gchar *bac_parse_dg1_mrz(const guint8 *dg1, gsize dg1_len);

/*
 * Reads the length of a BER-TLV tag+length header starting at data[0] and
 * returns the number of header bytes (tag+length encoding) via
 * *header_len_out and the declared content length via *content_len_out.
 * Needs at least 2 bytes; up to 4 to cover any length form actually seen
 * in eMRTD files. Returns FALSE if data is too short for the length form
 * it claims to use.
 */
gboolean bac_ber_tlv_header(const guint8 *data, gsize len, gsize *header_len_out,
                            gsize *content_len_out);

#endif

// vim:ts=4:sw=4:noexpandtab
