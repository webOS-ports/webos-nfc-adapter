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

#ifndef NDEF_H_
#define NDEF_H_

#include <glib.h>
#include <pbnjson.h>

/* Type Name Format, NFCForum-TS-NDEF_1.0 section 3.2.6 */
#define NDEF_TNF_EMPTY			0
#define NDEF_TNF_WELL_KNOWN		1
#define NDEF_TNF_MEDIA_TYPE		2
#define NDEF_TNF_ABSOLUTE_URI	3
#define NDEF_TNF_EXTERNAL		4
#define NDEF_TNF_UNKNOWN		5
#define NDEF_TNF_UNCHANGED		6

/**
 * Renders a single NDEF record as JSON. Always carries the raw fields (tnf,
 * type, id, payload as hex); well known types we understand are additionally
 * decoded into friendly fields such as "uri" or "text".
 */
jvalue_ref ndef_record_to_json(guint tnf, const guint8 *type, gsize type_len,
                               const guint8 *id, gsize id_len,
                               const guint8 *payload, gsize payload_len);

/**
 * Parses a complete NDEF message into a JSON array of records. Used for the
 * records nested inside a Smart Poster, and by anything holding a raw message.
 * Returns NULL if the message is malformed.
 */
jvalue_ref ndef_message_to_json(const guint8 *data, gsize len);

/* Encoders used by writeTag. Both return a single record message. */
GByteArray *ndef_build_uri_message(const char *uri);
GByteArray *ndef_build_text_message(const char *text, const char *language);

/**
 * Wraps an NDEF message in the Type 2 tag NDEF Message TLV (tag 0x03) and
 * appends the Terminator TLV (0xFE), which is what gets written to the tag's
 * data area.
 */
GByteArray *ndef_wrap_type2_tlv(const GByteArray *message);

gchar *ndef_bytes_to_hex(const guint8 *data, gsize len);

#endif

// vim:ts=4:sw=4:noexpandtab
