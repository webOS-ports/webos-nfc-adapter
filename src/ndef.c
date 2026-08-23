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

#include "ndef.h"

/* NDEF record header bits, NFCForum-TS-NDEF_1.0 section 3.2 */
#define NDEF_HDR_MB		0x80
#define NDEF_HDR_ME		0x40
#define NDEF_HDR_CF		0x20
#define NDEF_HDR_SR		0x10
#define NDEF_HDR_IL		0x08
#define NDEF_HDR_TNF	0x07

/* Abbreviations for the URI RTD, NFCForum-TS-RTD_URI_1.0 table 3 */
static const char * const uri_prefixes[] = {
	"",							/* 0x00 */
	"http://www.",				/* 0x01 */
	"https://www.",				/* 0x02 */
	"http://",					/* 0x03 */
	"https://",					/* 0x04 */
	"tel:",						/* 0x05 */
	"mailto:",					/* 0x06 */
	"ftp://anonymous:anonymous@",	/* 0x07 */
	"ftp://ftp.",				/* 0x08 */
	"ftps://",					/* 0x09 */
	"sftp://",					/* 0x0a */
	"smb://",					/* 0x0b */
	"nfs://",					/* 0x0c */
	"ftp://",					/* 0x0d */
	"dav://",					/* 0x0e */
	"news:",					/* 0x0f */
	"telnet://",				/* 0x10 */
	"imap:",					/* 0x11 */
	"rtsp://",					/* 0x12 */
	"urn:",						/* 0x13 */
	"pop:",						/* 0x14 */
	"sip:",						/* 0x15 */
	"sips:",					/* 0x16 */
	"tftp:",					/* 0x17 */
	"btspp://",					/* 0x18 */
	"btl2cap://",				/* 0x19 */
	"btgoep://",				/* 0x1a */
	"tcpobex://",				/* 0x1b */
	"irdaobex://",				/* 0x1c */
	"file://",					/* 0x1d */
	"urn:epc:id:",				/* 0x1e */
	"urn:epc:tag:",				/* 0x1f */
	"urn:epc:pat:",				/* 0x20 */
	"urn:epc:raw:",				/* 0x21 */
	"urn:epc:",					/* 0x22 */
	"urn:nfc:",					/* 0x23 */
};

gchar *ndef_bytes_to_hex(const guint8 *data, gsize len)
{
	GString *str;
	gsize n;

	if (!data || len == 0)
		return g_strdup("");

	str = g_string_sized_new(len * 2 + 1);

	for (n = 0; n < len; n++)
		g_string_append_printf(str, "%02x", data[n]);

	return g_string_free(str, FALSE);
}

/**
 * The type field of a well known record is a short ASCII token ("U", "T",
 * "Sp"), and media types are ASCII too, so it is worth exposing as a string.
 * Anything that isn't printable ASCII is left to the caller's hex rendering.
 */
static gchar *type_to_string(const guint8 *type, gsize type_len)
{
	gsize n;

	if (!type || type_len == 0)
		return NULL;

	for (n = 0; n < type_len; n++) {
		if (type[n] < 0x20 || type[n] > 0x7e)
			return NULL;
	}

	return g_strndup((const char *) type, type_len);
}

static gboolean type_equals(const guint8 *type, gsize type_len, const char *expected)
{
	gsize expected_len = strlen(expected);

	return type_len == expected_len && memcmp(type, expected, expected_len) == 0;
}

/**
 * URI record: a one byte abbreviation code followed by the rest of the URI,
 * NFCForum-TS-RTD_URI_1.0 section 3.
 */
static gchar *decode_uri_payload(const guint8 *payload, gsize payload_len)
{
	const char *prefix;
	guint8 code;

	if (payload_len < 1)
		return NULL;

	code = payload[0];
	prefix = (code < G_N_ELEMENTS(uri_prefixes)) ? uri_prefixes[code] : "";

	return g_strdup_printf("%s%.*s", prefix, (int) (payload_len - 1),
	                       (const char *) (payload + 1));
}

/**
 * Text record: status byte (bit 7 selects UTF-16, bits 5..0 hold the length of
 * the IANA language code) followed by the language code and the text itself,
 * NFCForum-TS-RTD_Text_1.0 section 3.
 */
static gboolean decode_text_payload(const guint8 *payload, gsize payload_len,
                                    gchar **out_text, gchar **out_language,
                                    gboolean *out_utf16)
{
	gsize lang_len;
	gboolean utf16;

	if (payload_len < 1)
		return FALSE;

	utf16 = (payload[0] & 0x80) != 0;
	lang_len = payload[0] & 0x3f;

	if (payload_len < 1 + lang_len)
		return FALSE;

	*out_language = g_strndup((const char *) (payload + 1), lang_len);
	*out_utf16 = utf16;

	if (utf16) {
		/* Rare in practice, but cheap to support properly */
		*out_text = g_utf16_to_utf8((const gunichar2 *) (payload + 1 + lang_len),
		                            (payload_len - 1 - lang_len) / 2,
		                            NULL, NULL, NULL);
	} else {
		*out_text = g_strndup((const char *) (payload + 1 + lang_len),
		                      payload_len - 1 - lang_len);
	}

	if (!*out_text) {
		g_free(*out_language);
		*out_language = NULL;
		return FALSE;
	}

	return TRUE;
}

jvalue_ref ndef_record_to_json(guint tnf, const guint8 *type, gsize type_len,
                               const guint8 *id, gsize id_len,
                               const guint8 *payload, gsize payload_len)
{
	jvalue_ref record_obj;
	gchar *hex;
	gchar *type_str;

	record_obj = jobject_create();

	jobject_put(record_obj, J_CSTR_TO_JVAL("tnf"), jnumber_create_i32(tnf));

	type_str = type_to_string(type, type_len);
	if (type_str) {
		jobject_put(record_obj, J_CSTR_TO_JVAL("type"), jstring_create(type_str));
		g_free(type_str);
	}

	hex = ndef_bytes_to_hex(type, type_len);
	jobject_put(record_obj, J_CSTR_TO_JVAL("typeHex"), jstring_create(hex));
	g_free(hex);

	if (id_len > 0) {
		hex = ndef_bytes_to_hex(id, id_len);
		jobject_put(record_obj, J_CSTR_TO_JVAL("idHex"), jstring_create(hex));
		g_free(hex);
	}

	hex = ndef_bytes_to_hex(payload, payload_len);
	jobject_put(record_obj, J_CSTR_TO_JVAL("payloadHex"), jstring_create(hex));
	g_free(hex);

	jobject_put(record_obj, J_CSTR_TO_JVAL("payloadSize"),
	            jnumber_create_i32((int) payload_len));

	switch (tnf) {
	case NDEF_TNF_WELL_KNOWN:
		if (type_equals(type, type_len, "U")) {
			gchar *uri = decode_uri_payload(payload, payload_len);

			if (uri) {
				jobject_put(record_obj, J_CSTR_TO_JVAL("kind"), jstring_create("uri"));
				jobject_put(record_obj, J_CSTR_TO_JVAL("uri"), jstring_create(uri));
				g_free(uri);
			}
		} else if (type_equals(type, type_len, "T")) {
			gchar *text = NULL, *language = NULL;
			gboolean utf16 = FALSE;

			if (decode_text_payload(payload, payload_len, &text, &language, &utf16)) {
				jobject_put(record_obj, J_CSTR_TO_JVAL("kind"), jstring_create("text"));
				jobject_put(record_obj, J_CSTR_TO_JVAL("text"), jstring_create(text));
				jobject_put(record_obj, J_CSTR_TO_JVAL("language"), jstring_create(language));
				jobject_put(record_obj, J_CSTR_TO_JVAL("utf16"), jboolean_create(utf16));
				g_free(text);
				g_free(language);
			}
		} else if (type_equals(type, type_len, "Sp")) {
			/* A Smart Poster wraps a whole NDEF message of its own */
			jvalue_ref nested = ndef_message_to_json(payload, payload_len);

			jobject_put(record_obj, J_CSTR_TO_JVAL("kind"), jstring_create("smartposter"));
			if (nested)
				jobject_put(record_obj, J_CSTR_TO_JVAL("records"), nested);
		}
		break;

	case NDEF_TNF_MEDIA_TYPE: {
		gchar *media_type = type_to_string(type, type_len);

		jobject_put(record_obj, J_CSTR_TO_JVAL("kind"), jstring_create("media"));
		if (media_type) {
			jobject_put(record_obj, J_CSTR_TO_JVAL("mediaType"), jstring_create(media_type));

			/* Hand text/... payloads over in readable form as a convenience */
			if (g_str_has_prefix(media_type, "text/") &&
			    g_utf8_validate((const char *) payload, payload_len, NULL)) {
				gchar *text = g_strndup((const char *) payload, payload_len);

				jobject_put(record_obj, J_CSTR_TO_JVAL("text"), jstring_create(text));
				g_free(text);
			}

			g_free(media_type);
		}
		break;
	}

	case NDEF_TNF_ABSOLUTE_URI: {
		gchar *uri = g_strndup((const char *) payload, payload_len);

		jobject_put(record_obj, J_CSTR_TO_JVAL("kind"), jstring_create("uri"));
		jobject_put(record_obj, J_CSTR_TO_JVAL("uri"), jstring_create(uri));
		g_free(uri);
		break;
	}

	case NDEF_TNF_EXTERNAL: {
		gchar *external = type_to_string(type, type_len);

		jobject_put(record_obj, J_CSTR_TO_JVAL("kind"), jstring_create("external"));
		if (external) {
			jobject_put(record_obj, J_CSTR_TO_JVAL("externalType"), jstring_create(external));
			g_free(external);
		}
		break;
	}

	default:
		break;
	}

	return record_obj;
}

jvalue_ref ndef_message_to_json(const guint8 *data, gsize len)
{
	jvalue_ref records_arr;
	gsize pos = 0;

	if (!data || len == 0)
		return NULL;

	records_arr = jarray_create(NULL);

	while (pos < len) {
		gsize type_len, payload_len, id_len = 0;
		const guint8 *type, *id = NULL, *payload;
		guint8 header;

		header = data[pos++];

		if (pos >= len)
			goto malformed;

		type_len = data[pos++];

		if (header & NDEF_HDR_SR) {
			if (pos >= len)
				goto malformed;
			payload_len = data[pos++];
		} else {
			if (pos + 4 > len)
				goto malformed;
			payload_len = ((gsize) data[pos] << 24) | ((gsize) data[pos + 1] << 16) |
			              ((gsize) data[pos + 2] << 8) | (gsize) data[pos + 3];
			pos += 4;
		}

		if (header & NDEF_HDR_IL) {
			if (pos >= len)
				goto malformed;
			id_len = data[pos++];
		}

		if (pos + type_len + id_len + payload_len > len)
			goto malformed;

		type = data + pos;
		pos += type_len;

		if (id_len > 0) {
			id = data + pos;
			pos += id_len;
		}

		payload = data + pos;
		pos += payload_len;

		jarray_append(records_arr,
		              ndef_record_to_json(header & NDEF_HDR_TNF, type, type_len,
		                                  id, id_len, payload, payload_len));

		if (header & NDEF_HDR_ME)
			break;
	}

	return records_arr;

malformed:
	j_release(&records_arr);
	return NULL;
}

/* Builds a single short record carrying both the MB and ME flags */
static GByteArray *build_single_record(guint tnf, const char *type,
                                       const guint8 *payload, gsize payload_len)
{
	GByteArray *message;
	guint8 header;
	guint8 type_len = (guint8) strlen(type);

	message = g_byte_array_new();

	/*
	 * Short record form only carries a one byte length, so anything larger
	 * would need the long form. Tags we can write this way are far smaller
	 * than that anyway, so refuse rather than silently truncate.
	 */
	if (payload_len > 0xff) {
		g_byte_array_free(message, TRUE);
		return NULL;
	}

	header = NDEF_HDR_MB | NDEF_HDR_ME | NDEF_HDR_SR | (tnf & NDEF_HDR_TNF);

	g_byte_array_append(message, &header, 1);
	g_byte_array_append(message, &type_len, 1);

	{
		guint8 len_byte = (guint8) payload_len;

		g_byte_array_append(message, &len_byte, 1);
	}

	g_byte_array_append(message, (const guint8 *) type, type_len);

	if (payload_len > 0)
		g_byte_array_append(message, payload, payload_len);

	return message;
}

GByteArray *ndef_build_uri_message(const char *uri)
{
	GByteArray *message;
	GByteArray *payload;
	guint8 best_code = 0;
	gsize best_len = 0;
	guint8 code;
	gsize n;

	if (!uri)
		return NULL;

	/* Pick the longest abbreviation that matches, to keep the record small */
	for (n = 1; n < G_N_ELEMENTS(uri_prefixes); n++) {
		gsize prefix_len = strlen(uri_prefixes[n]);

		if (prefix_len > best_len && g_str_has_prefix(uri, uri_prefixes[n])) {
			best_len = prefix_len;
			best_code = (guint8) n;
		}
	}

	code = best_code;

	payload = g_byte_array_new();
	g_byte_array_append(payload, &code, 1);
	g_byte_array_append(payload, (const guint8 *) (uri + best_len),
	                    strlen(uri) - best_len);

	message = build_single_record(NDEF_TNF_WELL_KNOWN, "U", payload->data, payload->len);

	g_byte_array_free(payload, TRUE);

	return message;
}

GByteArray *ndef_build_text_message(const char *text, const char *language)
{
	GByteArray *message;
	GByteArray *payload;
	gsize lang_len;
	guint8 status;

	if (!text)
		return NULL;

	if (!language || !*language)
		language = "en";

	lang_len = strlen(language);

	/* The status byte only has six bits for the language code length */
	if (lang_len > 0x3f)
		return NULL;

	status = (guint8) lang_len;	/* bit 7 clear: the text is UTF-8 */

	payload = g_byte_array_new();
	g_byte_array_append(payload, &status, 1);
	g_byte_array_append(payload, (const guint8 *) language, lang_len);
	g_byte_array_append(payload, (const guint8 *) text, strlen(text));

	message = build_single_record(NDEF_TNF_WELL_KNOWN, "T", payload->data, payload->len);

	g_byte_array_free(payload, TRUE);

	return message;
}

GByteArray *ndef_wrap_type2_tlv(const GByteArray *message)
{
	GByteArray *tlv;
	guint8 tag = 0x03;			/* NDEF Message TLV */
	guint8 terminator = 0xfe;	/* Terminator TLV */

	if (!message)
		return NULL;

	tlv = g_byte_array_new();
	g_byte_array_append(tlv, &tag, 1);

	if (message->len < 0xff) {
		guint8 len_byte = (guint8) message->len;

		g_byte_array_append(tlv, &len_byte, 1);
	} else {
		/* Three byte form: 0xFF followed by a big endian 16 bit length */
		guint8 len_bytes[3];

		len_bytes[0] = 0xff;
		len_bytes[1] = (guint8) (message->len >> 8);
		len_bytes[2] = (guint8) (message->len & 0xff);
		g_byte_array_append(tlv, len_bytes, 3);
	}

	g_byte_array_append(tlv, message->data, message->len);
	g_byte_array_append(tlv, &terminator, 1);

	return tlv;
}

// vim:ts=4:sw=4:noexpandtab
