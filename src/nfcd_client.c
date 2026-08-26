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
#include <gio/gio.h>

#include "nfcd-interface.h"
#include "nfcd_client.h"
#include "ndef.h"
#include "bac.h"
#include "pace.h"

#define NFCD_DAEMON_SERVICE		"org.sailfishos.nfc.daemon"
#define NFCD_SETTINGS_SERVICE	"org.sailfishos.nfc.settings"
#define NFCD_ROOT_PATH			"/"
#define NFCD_HCE_OBJECT_PATH		"/org/webosports/nfc/hce"
#define NFCD_HCE_APP_NAME		"webos-nfc-adapter"

#define TAG_IFACE_TYPE2			"org.sailfishos.nfc.TagType2"

/* NfcTag.type value for MIFARE Classic (nfc_types.h NFC_TAG_TYPE enum) */
#define NFC_TAG_TYPE_MIFARE_CLASSIC	2

/* org.sailfishos.nfc.Tag.xml protocol codes: ISO-DEP over NFC-A/-B - what
 * ICAO 9303 eMRTD chips (passports, eIDs) activate as. */
#define NFC_PROTOCOL_T4A	8
#define NFC_PROTOCOL_T4B	16

/* org.sailfishos.nfc.Daemon polling bit: see Daemon.xml */
#define NFCD_MODE_READER_WRITER	0x02
#define NFCD_MODE_CARD_EMULATION	0x08

struct tag_read;

struct nfcd_client {
	guint daemon_watch;
	guint settings_watch;

	NfcdInterfaceDaemon *daemon;
	NfcdInterfaceAdapter *adapter;
	NfcdInterfaceSettings *settings;

	/* Cancelled when the client goes away, so in-flight calls don't come
	 * back to freed memory */
	GCancellable *cancellable;

	gchar *adapter_path;
	gboolean available;
	gboolean powered;
	gboolean present;
	guint mode;
	guint supported_modes;
	guint techs;
	gint daemon_version;

	/* Reader/writer mode we hold on the daemon for our whole lifetime, so
	 * any client that shows up (ndef-read included) finds the radio already
	 * polling. nfcd releases it on its own if our bus connection drops, the
	 * same as every other resource it hands out (Tag.Acquire and friends),
	 * so there is nothing to release explicitly on our own shutdown. 0 means
	 * "not currently held".
	 */
	guint mode_request_id;

	/* The enabled flag is owned by the settings plugin, but the adapter
	 * reports it too. Prefer the settings value when we have it. */
	gboolean settings_valid;
	gboolean settings_enabled;
	gboolean adapter_enabled;

	gchar *tag_path;
	gboolean tag_is_type2;
	guint tag_protocol;		/* org.sailfishos.nfc.Tag.xml protocol code, see protocol_to_string() */
	jvalue_ref tag_json;
	struct tag_read *reading;

	/* At most one passport BAC read at a time - see nfcd_client_read_passport() */
	struct passport_read *passport_reading;

	/* MIFARE Classic keys that worked before, by tag UID (hex string) ->
	 * struct mifare_key_cache_entry*, so re-taps of the same physical
	 * tag skip straight to the known key instead of re-guessing. */
	GHashTable *mifare_key_cache;

	nfcd_state_cb state_cb;
	nfcd_tag_cb tag_cb;
	nfcd_hce_cb hce_cb;
	void *user_data;

	/* Card emulation: one struct hce_profile per registered AID, keyed
	 * by its hex string. See nfcd_client_add_card_emulation_profile(). */
	GHashTable *hce_profiles;
	guint hce_mode_request_id;

	/* Most recent reader-confirmed exchange, for getHceEvent */
	gchar *hce_event_aid_hex;
	gboolean hce_event_ok;
};

#define MIFARE_KEY_LEN 6
#define MIFARE_NUM_SECTORS 40

/*
 * Well-known, publicly-documented default MIFARE Classic keys only
 * (factory default, NFC Forum MAD, NFC Forum NDEF, blank/programmer) -
 * deliberately not a key-cracking attempt. A sector using any other key
 * (as any real transit/payment card will) is simply left unread.
 */
static const guint8 mifare_default_keys[][MIFARE_KEY_LEN] = {
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 },
	{ 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};
#define MIFARE_NUM_DEFAULT_KEYS (G_N_ELEMENTS(mifare_default_keys))

/* Per-UID cache of keys that authenticated successfully before */
struct mifare_key_cache_entry {
	guint8 keys[MIFARE_NUM_SECTORS][MIFARE_KEY_LEN];
	gboolean has_key[MIFARE_NUM_SECTORS];
};

/* One sequential walk over a tag and its NDEF records (or, for MIFARE
 * Classic, its sectors - see tag_read_mifare_start()) */
struct tag_read {
	struct nfcd_client *client;		/* NULL once orphaned */
	gchar *path;
	NfcdInterfaceTag *tag;
	jvalue_ref tag_obj;
	jvalue_ref records_arr;
	gchar **record_paths;
	guint record_index;
	gboolean is_type2;
	GCancellable *cancellable;

	gboolean is_mifare;
	gchar *mifare_uid;		/* hex NFCID1, used as the cache key */
	guint mifare_sector;
	guint mifare_key_index;
	guint mifare_auth_type;	/* 0 = key A (0x60), 1 = key B (0x61) */
	guint mifare_block_offset;	/* block within the sector, once authed */
	guint8 mifare_key[MIFARE_KEY_LEN];
	gboolean mifare_cached_attempt;	/* trying the cached key for this sector */
	jvalue_ref mifare_sectors_arr;
	jvalue_ref mifare_blocks_arr;
};

/* One passport/eID read via BAC or PACE: (BAC: SELECT eMRTD app, GET
 * CHALLENGE, MUTUAL AUTHENTICATE) or (PACE: MSE:Set AT, 4 General
 * Authenticate rounds, then SELECT eMRTD app under secure messaging),
 * then EF.DG1 under secure messaging either way. See bac.h/pace.h. */
struct passport_read {
	struct nfcd_client *client;		/* NULL once orphaned */
	NfcdInterfaceTag *tag;
	GCancellable *cancellable;

	gboolean use_pace;

	/* BAC path */
	BacStaticKeys keys;
	BacChallenge challenge;
	BacSession session;
	guint8 rnd_icc[8];

	/* PACE path */
	GByteArray *pace_k;		/* password encoding, until EF.CardAccess picks a curve */
	GByteArray *card_access;	/* accumulated EF.CardAccess bytes */
	gsize card_access_total_len;	/* from the first chunk's TLV header */
	guint8 pace_selected_oid[16];
	gsize pace_selected_oid_len;
	PaceExchange *pace;
	PaceSession pace_session;

	GByteArray *dg1;		/* accumulated EF.DG1 bytes */
	gsize dg1_total_len;		/* from the first 4 bytes' TLV header */

	nfcd_passport_cb cb;
	void *user_data;
};

struct write_req {
	struct nfcd_client *client;
	GByteArray *tlv;
	NfcdInterfaceTag *tag;
	NfcdInterfaceTagType2 *type2;
	nfcd_result_cb cb;
	void *user_data;
	gboolean written;
	/* Set when something failed after the tag was acquired, so that the
	 * release step can still report what actually went wrong. */
	gchar *error_text;
};

struct simple_req {
	struct nfcd_client *client;
	nfcd_result_cb cb;
	void *user_data;
};

static void tag_read_start(struct nfcd_client *client, const char *path);
static void tag_read_next_record(struct tag_read *read);
static void tag_read_free(struct tag_read *read);
static void tag_read_finish(struct tag_read *read);

static void tag_read_mifare_start(struct tag_read *read);
static void tag_read_mifare_next_sector(struct tag_read *read);
static void tag_read_mifare_try_key(struct tag_read *read);
static void mifare_read_block(struct tag_read *read, guint block);
static void mifare_sector_done(struct tag_read *read);
static void mifare_publish_progress(struct tag_read *read);
static gboolean mifare_try_cached_key(struct tag_read *read);

static void passport_read_abort(struct passport_read *read);
static void passport_select_aid_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void passport_get_challenge_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void passport_mutual_auth_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void passport_select_dg1_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void passport_dg1_rest_ready(GObject *source, GAsyncResult *res, gpointer user_data);

static void passport_select_ef_cardaccess_ready(GObject *source, GAsyncResult *res,
                                                gpointer user_data);
static void passport_ef_cardaccess_rest_ready(GObject *source, GAsyncResult *res,
                                              gpointer user_data);
static void pace_mse_set_at_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void pace_get_nonce_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void pace_map_nonce_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void pace_key_agreement_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void pace_mutual_auth_ready(GObject *source, GAsyncResult *res, gpointer user_data);
static void pace_select_aid_ready(GObject *source, GAsyncResult *res, gpointer user_data);

static void notify_state(struct nfcd_client *client)
{
	if (client->state_cb)
		client->state_cb(client, client->user_data);
}

static void notify_tag(struct nfcd_client *client)
{
	if (client->tag_cb)
		client->tag_cb(client, client->user_data);
}

/*
 * Helpers to render the GVariant blobs nfcd hands back (poll parameters and
 * the like) as something a JSON consumer can use.
 */

static jvalue_ref variant_to_json(GVariant *value)
{
	const GVariantType *type = g_variant_get_type(value);

	if (g_variant_type_equal(type, G_VARIANT_TYPE_BYTESTRING) ||
	    g_variant_type_equal(type, G_VARIANT_TYPE("ay"))) {
		gsize len = 0;
		const guint8 *data = g_variant_get_fixed_array(value, &len, 1);
		gchar *hex = ndef_bytes_to_hex(data, len);
		jvalue_ref result = jstring_create(hex);

		g_free(hex);
		return result;
	}

	if (g_variant_type_equal(type, G_VARIANT_TYPE_STRING))
		return jstring_create(g_variant_get_string(value, NULL));

	if (g_variant_type_equal(type, G_VARIANT_TYPE_BOOLEAN))
		return jboolean_create(g_variant_get_boolean(value));

	if (g_variant_type_equal(type, G_VARIANT_TYPE_BYTE))
		return jnumber_create_i32(g_variant_get_byte(value));

	if (g_variant_type_equal(type, G_VARIANT_TYPE_UINT32))
		return jnumber_create_i32((int) g_variant_get_uint32(value));

	if (g_variant_type_equal(type, G_VARIANT_TYPE_INT32))
		return jnumber_create_i32(g_variant_get_int32(value));

	/* Nothing we specifically know about: at least say what it was */
	{
		gchar *text = g_variant_print(value, FALSE);
		jvalue_ref result = jstring_create(text);

		g_free(text);
		return result;
	}
}

static jvalue_ref variant_dict_to_json(GVariant *dict)
{
	jvalue_ref obj = jobject_create();
	GVariantIter iter;
	const gchar *key;
	GVariant *value;

	if (!dict)
		return obj;

	g_variant_iter_init(&iter, dict);
	while (g_variant_iter_next(&iter, "{&sv}", &key, &value)) {
		jobject_put(obj, jstring_create(key), variant_to_json(value));
		g_variant_unref(value);
	}

	return obj;
}

/* Technology and protocol codes are documented in org.sailfishos.nfc.Tag.xml */
static const char *technology_to_string(guint technology)
{
	switch (technology) {
	case 1: return "nfc-a";
	case 2: return "nfc-b";
	case 4: return "nfc-f";
	default: return "unknown";
	}
}

static const char *protocol_to_string(guint protocol)
{
	switch (protocol) {
	case 1: return "t1t";
	case 2: return "t2t";
	case 4: return "t3t";
	case 8: return "t4a";
	case 16: return "t4b";
	case 32: return "nfc-dep";
	case 64: return "mifare-classic";
	default: return "unknown";
	}
}

static jvalue_ref strv_to_json(gchar **strv)
{
	jvalue_ref arr = jarray_create(NULL);
	guint n;

	if (strv) {
		for (n = 0; strv[n]; n++)
			jarray_append(arr, jstring_create(strv[n]));
	}

	return arr;
}

/*
 * Tag reading. The chain is strictly sequential, so at most one asynchronous
 * call is outstanding per read and the callback can safely free the read once
 * it has been abandoned.
 */

static void tag_read_free(struct tag_read *read)
{
	if (!read)
		return;

	if (read->tag)
		g_object_unref(read->tag);

	if (read->cancellable)
		g_object_unref(read->cancellable);

	if (read->tag_obj)
		j_release(&read->tag_obj);

	if (read->records_arr)
		j_release(&read->records_arr);

	if (read->mifare_sectors_arr)
		j_release(&read->mifare_sectors_arr);

	if (read->mifare_blocks_arr)
		j_release(&read->mifare_blocks_arr);

	g_strfreev(read->record_paths);
	g_free(read->mifare_uid);
	g_free(read->path);
	g_free(read);
}

/* Detaches a read from its client so its pending callback just cleans up */
static void tag_read_abort(struct tag_read *read)
{
	if (!read)
		return;

	read->client = NULL;
	g_cancellable_cancel(read->cancellable);
}

static void tag_read_finish(struct tag_read *read)
{
	struct nfcd_client *client = read->client;

	if (!client) {
		tag_read_free(read);
		return;
	}

	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("records"), read->records_arr);
	read->records_arr = NULL;

	if (client->tag_json)
		j_release(&client->tag_json);

	client->tag_json = read->tag_obj;
	read->tag_obj = NULL;

	client->tag_is_type2 = read->is_type2;
	client->reading = NULL;

	tag_read_free(read);

	notify_tag(client);
}

/*
 * MIFARE Classic auth+read. Sectors 0-31 have 4 blocks each; sectors
 * 32-39 (only present on 4K cards) have 16 blocks each - standard MIFARE
 * Classic layout, not vendor-specific.
 */
static guint mifare_sector_first_block(guint sector)
{
	return (sector < 32) ? sector * 4 : 128 + (sector - 32) * 16;
}

static guint mifare_sector_block_count(guint sector)
{
	return (sector < 32) ? 4 : 16;
}

static gboolean mifare_cache_lookup(struct nfcd_client *client, const gchar *uid,
                                    guint sector, guint8 *key_out)
{
	struct mifare_key_cache_entry *entry;

	if (!uid || !client->mifare_key_cache)
		return FALSE;

	entry = g_hash_table_lookup(client->mifare_key_cache, uid);
	if (entry && entry->has_key[sector]) {
		memcpy(key_out, entry->keys[sector], MIFARE_KEY_LEN);
		return TRUE;
	}
	return FALSE;
}

static void mifare_cache_store(struct nfcd_client *client, const gchar *uid,
                               guint sector, const guint8 *key)
{
	struct mifare_key_cache_entry *entry;

	if (!uid || !client->mifare_key_cache)
		return;

	entry = g_hash_table_lookup(client->mifare_key_cache, uid);
	if (!entry) {
		entry = g_new0(struct mifare_key_cache_entry, 1);
		g_hash_table_insert(client->mifare_key_cache, g_strdup(uid), entry);
	}
	memcpy(entry->keys[sector], key, MIFARE_KEY_LEN);
	entry->has_key[sector] = TRUE;
}

static void tag_read_mifare_start(struct tag_read *read)
{
	read->is_mifare = TRUE;
	read->mifare_sector = 0;
	read->mifare_sectors_arr = jarray_create(NULL);
	tag_read_mifare_next_sector(read);
}

/*
 * A full sector sweep can take a while (see MIFARE_TAG_TIMEOUT_SEC in
 * libnciplugin's nci_adapter.c). Publish a snapshot of whatever has been
 * found so far after each sector, so getTagInfo subscribers see progress
 * instead of nothing until the whole sweep completes.
 */
static void mifare_publish_progress(struct tag_read *read)
{
	jvalue_ref snapshot;

	if (!read->client)
		return;

	snapshot = jvalue_duplicate(read->tag_obj);
	jobject_put(snapshot, J_CSTR_TO_JVAL("sectors"),
	            jvalue_duplicate(read->mifare_sectors_arr));
	jobject_put(snapshot, J_CSTR_TO_JVAL("scanning"), jboolean_create(TRUE));

	if (read->client->tag_json)
		j_release(&read->client->tag_json);
	read->client->tag_json = snapshot;

	notify_tag(read->client);
}

static void tag_read_mifare_next_sector(struct tag_read *read)
{
	if (!read->client) {
		tag_read_free(read);
		return;
	}

	if (read->mifare_sector >= MIFARE_NUM_SECTORS) {
		jobject_put(read->tag_obj, J_CSTR_TO_JVAL("sectors"),
		            read->mifare_sectors_arr);
		read->mifare_sectors_arr = NULL;
		jobject_put(read->tag_obj, J_CSTR_TO_JVAL("scanning"),
		            jboolean_create(FALSE));
		tag_read_finish(read);
		return;
	}

	mifare_publish_progress(read);

	read->mifare_key_index = 0;
	read->mifare_auth_type = 0;
	read->mifare_cached_attempt = FALSE;

	if (!mifare_try_cached_key(read))
		tag_read_mifare_try_key(read);
}

static void mifare_auth_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);

	if (!read->client) {
		if (response)
			g_variant_unref(response);
		if (error)
			g_error_free(error);
		tag_read_free(read);
		return;
	}

	if (!ok) {
		gboolean cancelled = g_error_matches(error, G_IO_ERROR,
		                                     G_IO_ERROR_CANCELLED);
		g_error_free(error);
		if (cancelled) {
			tag_read_free(read);
		} else if (read->mifare_cached_attempt) {
			/* Cached key no longer works (tag re-keyed?) - fall
			 * back to the normal default-key sweep */
			read->mifare_cached_attempt = FALSE;
			tag_read_mifare_try_key(read);
		} else {
			/* Most likely just the wrong key for this sector */
			read->mifare_key_index++;
			tag_read_mifare_try_key(read);
		}
		return;
	}

	if (response)
		g_variant_unref(response);

	/*
	 * A clean Transceive() round-trip on the auth command doesn't by
	 * itself guarantee the key was right - the vendor HAL can signal a
	 * failed auth with a normal-looking short response rather than a
	 * transport error. Read the sector's first block back for real;
	 * only actual block data confirms the key worked.
	 */
	read->mifare_block_offset = 0;
	read->mifare_blocks_arr = jarray_create(NULL);
	mifare_read_block(read, mifare_sector_first_block(read->mifare_sector));
}

static void mifare_send_auth(struct tag_read *read, const guint8 *key)
{
	guint8 cmd[12];
	guint block = mifare_sector_first_block(read->mifare_sector);
	GVariant *data;

	memcpy(read->mifare_key, key, MIFARE_KEY_LEN);

	/*
	 * Vendor MIFARE auth extension command, reverse-engineered from the
	 * NXP HAL (NxpMfcReader::BuildAuthCmd/BuildMfcCmd in
	 * /vendor/lib64/nfc_nci_nxp.so): byte 0 = 0x60 (key A) or 0x61
	 * (key B), byte 1 = any block number within the target sector (the
	 * HAL derives the sector address from it internally), bytes 2-5
	 * unused, bytes 6-11 = the 6-byte key. Total 12 bytes - the key
	 * lands at the right offset only when the buffer is exactly this
	 * shape, since the HAL just copies our raw input into its own
	 * struct and reads the key back out at a fixed offset.
	 */
	cmd[0] = read->mifare_auth_type ? 0x61 : 0x60;
	cmd[1] = (guint8) block;
	memset(cmd + 2, 0, 4);
	memcpy(cmd + 6, read->mifare_key, MIFARE_KEY_LEN);

	data = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, cmd, sizeof(cmd), 1);
	nfcd_interface_tag_call_transceive(read->tag, data, read->cancellable,
	                                   mifare_auth_ready, read);
}

/* Returns TRUE if a cached-key attempt was started (async, callback will
 * fall back to the normal sweep on failure - see mifare_auth_ready()) */
static gboolean mifare_try_cached_key(struct tag_read *read)
{
	guint8 key[MIFARE_KEY_LEN];

	if (!mifare_cache_lookup(read->client, read->mifare_uid,
	                         read->mifare_sector, key))
		return FALSE;

	read->mifare_cached_attempt = TRUE;
	read->mifare_auth_type = 0;
	mifare_send_auth(read, key);
	return TRUE;
}

static void tag_read_mifare_try_key(struct tag_read *read)
{
	if (read->mifare_key_index >= MIFARE_NUM_DEFAULT_KEYS) {
		/*
		 * Key B is deliberately not tried by default - real-world
		 * tags rarely need it beyond key A, and every key doubles
		 * the worst-case sweep time (40 sectors x 4 keys is already
		 * ~160 round-trips when nothing authenticates). Give up on
		 * this sector and move on.
		 */
		read->mifare_sector++;
		tag_read_mifare_next_sector(read);
		return;
	}

	if (!read->client) {
		tag_read_free(read);
		return;
	}

	mifare_send_auth(read, mifare_default_keys[read->mifare_key_index]);
}

static void mifare_block_read_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);

	if (!read->client) {
		if (response)
			g_variant_unref(response);
		if (error)
			g_error_free(error);
		tag_read_free(read);
		return;
	}

	if (ok) {
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);

		/* Real MIFARE Classic blocks are exactly 16 bytes */
		if (len == 16) {
			gchar *hex = ndef_bytes_to_hex(bytes, len);

			jarray_append(read->mifare_blocks_arr, jstring_create(hex));
			g_free(hex);
			g_variant_unref(response);

			read->mifare_block_offset++;
			if (read->mifare_block_offset >=
			    mifare_sector_block_count(read->mifare_sector)) {
				mifare_sector_done(read);
			} else {
				mifare_read_block(read, mifare_sector_first_block(
					read->mifare_sector) + read->mifare_block_offset);
			}
			return;
		}
		g_variant_unref(response);
	} else {
		g_error_free(error);
	}

	if (read->mifare_block_offset == 0) {
		/* Wrong key after all - the auth round-trip looked clean but
		 * the very first read failed. j_release() leaves the pointer
		 * undefined (not NULL, see japi.h) - null it ourselves so
		 * tag_read_free()'s "if (x) j_release(x)" guard doesn't see
		 * stale garbage and release it a second time later. */
		j_release(&read->mifare_blocks_arr);
		read->mifare_blocks_arr = NULL;
		if (read->mifare_cached_attempt) {
			read->mifare_cached_attempt = FALSE;
			tag_read_mifare_try_key(read);
		} else {
			read->mifare_key_index++;
			tag_read_mifare_try_key(read);
		}
	} else {
		/* Odd mid-sector hiccup on an otherwise-good key - keep what
		 * we already read and move on rather than losing the sector */
		mifare_sector_done(read);
	}
}

static void mifare_read_block(struct tag_read *read, guint block)
{
	guint8 cmd[2];
	GVariant *data;

	/*
	 * Standard MIFARE Classic READ (0x30 + block number), not a vendor
	 * extension - the HAL's BuildMfcCmd default path just prefixes a
	 * "raw frame" marker and forwards this verbatim, appending CRC as
	 * normal. Only valid once a sector has been successfully
	 * authenticated (see tag_read_mifare_try_key()).
	 */
	cmd[0] = 0x30;
	cmd[1] = (guint8) block;

	data = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, cmd, sizeof(cmd), 1);
	nfcd_interface_tag_call_transceive(read->tag, data, read->cancellable,
	                                   mifare_block_read_ready, read);
}

static void mifare_sector_done(struct tag_read *read)
{
	jvalue_ref sector_obj = jobject_create();
	gchar *key_hex = ndef_bytes_to_hex(read->mifare_key, MIFARE_KEY_LEN);

	jobject_put(sector_obj, J_CSTR_TO_JVAL("sector"),
	            jnumber_create_i32((int) read->mifare_sector));
	jobject_put(sector_obj, J_CSTR_TO_JVAL("keyType"),
	            jstring_create(read->mifare_auth_type ? "B" : "A"));
	jobject_put(sector_obj, J_CSTR_TO_JVAL("key"), jstring_create(key_hex));
	g_free(key_hex);
	jobject_put(sector_obj, J_CSTR_TO_JVAL("blocks"), read->mifare_blocks_arr);
	read->mifare_blocks_arr = NULL;

	jarray_append(read->mifare_sectors_arr, sector_obj);

	mifare_cache_store(read->client, read->mifare_uid, read->mifare_sector,
	                   read->mifare_key);

	read->mifare_sector++;
	tag_read_mifare_next_sector(read);
}

static void ndef_get_all_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	NfcdInterfaceNDEF *ndef = NFCD_INTERFACE_NDEF(source);
	GError *error = NULL;
	gint version = 0;
	guint flags = 0, tnf = 0;
	gchar **interfaces = NULL;
	GVariant *type = NULL, *id = NULL, *payload = NULL;

	if (nfcd_interface_ndef_call_get_all_finish(ndef, &version, &flags, &tnf,
	                                            &interfaces, &type, &id, &payload,
	                                            res, &error)) {
		if (read->client) {
			gsize type_len = 0, id_len = 0, payload_len = 0;
			const guint8 *type_data = g_variant_get_fixed_array(type, &type_len, 1);
			const guint8 *id_data = g_variant_get_fixed_array(id, &id_len, 1);
			const guint8 *payload_data = g_variant_get_fixed_array(payload, &payload_len, 1);

			jarray_append(read->records_arr,
			              ndef_record_to_json(tnf, type_data, type_len,
			                                  id_data, id_len,
			                                  payload_data, payload_len));
		}

		g_strfreev(interfaces);
		g_variant_unref(type);
		g_variant_unref(id);
		g_variant_unref(payload);
	} else {
		/* A record we can't read is not fatal: the tag may have been taken
		 * out of the field halfway through. Keep whatever we already have. */
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to read NDEF record: %s", error->message);
		g_error_free(error);
	}

	g_object_unref(ndef);

	if (!read->client) {
		tag_read_free(read);
		return;
	}

	read->record_index++;
	tag_read_next_record(read);
}

static void ndef_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	GError *error = NULL;
	NfcdInterfaceNDEF *ndef;

	ndef = nfcd_interface_ndef_proxy_new_for_bus_finish(res, &error);

	if (!ndef) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to create NDEF proxy: %s", error->message);
		g_error_free(error);

		if (!read->client) {
			tag_read_free(read);
			return;
		}

		read->record_index++;
		tag_read_next_record(read);
		return;
	}

	if (!read->client) {
		g_object_unref(ndef);
		tag_read_free(read);
		return;
	}

	nfcd_interface_ndef_call_get_all(ndef, read->cancellable,
	                                 ndef_get_all_ready, read);
}

/*
 * Type 2 tags additionally get their whole data area read back as one raw
 * hex blob ("rawDataHex" in the tag JSON), independent of however many NDEF
 * records nfcd parsed out of it. This is what cloneTag replays verbatim to
 * another tag: writing the individually-decoded records back out could
 * subtly change bytes nfcd didn't have a friendly decoding for, where the
 * raw bytes round-trip exactly.
 */

static void raw_data_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	NfcdInterfaceTagType2 *type2 = NFCD_INTERFACE_TAG_TYPE2(source);
	GError *error = NULL;
	GVariant *data = NULL;

	if (nfcd_interface_tag_type2_call_read_all_data_finish(type2, &data, res, &error)) {
		if (read->client) {
			gsize len = 0;
			const guint8 *bytes = g_variant_get_fixed_array(data, &len, 1);
			gchar *hex = ndef_bytes_to_hex(bytes, len);

			jobject_put(read->tag_obj, J_CSTR_TO_JVAL("rawDataHex"), jstring_create(hex));
			g_free(hex);
		}

		g_variant_unref(data);
	} else {
		/* Not fatal to the read as a whole - cloning just won't be possible */
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to read raw tag data: %s", error->message);
		g_error_free(error);
	}

	g_object_unref(type2);

	if (!read->client) {
		tag_read_free(read);
		return;
	}

	tag_read_finish(read);
}

static void raw_data_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	GError *error = NULL;
	NfcdInterfaceTagType2 *type2;

	type2 = nfcd_interface_tag_type2_proxy_new_for_bus_finish(res, &error);

	if (!type2) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to create TagType2 proxy for raw read: %s", error->message);
		g_error_free(error);

		if (!read->client) {
			tag_read_free(read);
			return;
		}

		tag_read_finish(read);
		return;
	}

	if (!read->client) {
		g_object_unref(type2);
		tag_read_free(read);
		return;
	}

	nfcd_interface_tag_type2_call_read_all_data(type2, read->cancellable,
	                                            raw_data_ready, read);
}

static void tag_read_raw_data(struct tag_read *read)
{
	if (!read->is_type2) {
		tag_read_finish(read);
		return;
	}

	nfcd_interface_tag_type2_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                           NFCD_DAEMON_SERVICE, read->path,
	                                           read->cancellable,
	                                           raw_data_proxy_ready, read);
}

static void tag_read_next_record(struct tag_read *read)
{
	const char *path;

	if (!read->record_paths || !read->record_paths[read->record_index]) {
		tag_read_raw_data(read);
		return;
	}

	path = read->record_paths[read->record_index];

	nfcd_interface_ndef_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                      NFCD_DAEMON_SERVICE, path,
	                                      read->cancellable, ndef_proxy_ready, read);
}

static void tag_get_all_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	NfcdInterfaceTag *tag = NFCD_INTERFACE_TAG(source);
	GError *error = NULL;
	gint version = 0;
	gboolean present = FALSE;
	guint technology = 0, protocol = 0, type = 0;
	gchar **interfaces = NULL;
	gchar **ndef_records = NULL;
	GVariant *poll_parameters = NULL;
	guint n;

	if (!nfcd_interface_tag_call_get_all3_finish(tag, &version, &present,
	                                             &technology, &protocol, &type,
	                                             &interfaces, &ndef_records,
	                                             &poll_parameters, res, &error)) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to read tag %s: %s", read->path, error->message);
		g_error_free(error);

		if (read->client)
			read->client->reading = NULL;

		tag_read_free(read);
		return;
	}

	if (!read->client) {
		g_strfreev(interfaces);
		g_strfreev(ndef_records);
		g_variant_unref(poll_parameters);
		tag_read_free(read);
		return;
	}

	read->tag_obj = jobject_create();
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("path"), jstring_create(read->path));
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("present"), jboolean_create(present));
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("technology"),
	            jstring_create(technology_to_string(technology)));
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("protocol"),
	            jstring_create(protocol_to_string(protocol)));
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("type"), jnumber_create_i32((int) type));
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("interfaces"), strv_to_json(interfaces));
	jobject_put(read->tag_obj, J_CSTR_TO_JVAL("pollParameters"),
	            variant_dict_to_json(poll_parameters));

	read->client->tag_protocol = protocol;

	for (n = 0; interfaces && interfaces[n]; n++) {
		if (!g_strcmp0(interfaces[n], TAG_IFACE_TYPE2))
			read->is_type2 = TRUE;
	}

	read->records_arr = jarray_create(NULL);
	read->record_paths = ndef_records;
	read->record_index = 0;

	if (type == NFC_TAG_TYPE_MIFARE_CLASSIC) {
		GVariant *nfcid1 = g_variant_lookup_value(poll_parameters, "NFCID1",
		                                          G_VARIANT_TYPE("ay"));

		if (nfcid1) {
			gsize len = 0;
			const guint8 *bytes = g_variant_get_fixed_array(nfcid1, &len, 1);

			read->mifare_uid = ndef_bytes_to_hex(bytes, len);
			g_variant_unref(nfcid1);
		}
	}

	g_strfreev(interfaces);
	g_variant_unref(poll_parameters);

	if (type == NFC_TAG_TYPE_MIFARE_CLASSIC)
		tag_read_mifare_start(read);
	else
		tag_read_next_record(read);
}

static void tag_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct tag_read *read = user_data;
	GError *error = NULL;

	read->tag = nfcd_interface_tag_proxy_new_for_bus_finish(res, &error);

	if (!read->tag) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to create tag proxy for %s: %s", read->path, error->message);
		g_error_free(error);

		if (read->client)
			read->client->reading = NULL;

		tag_read_free(read);
		return;
	}

	if (!read->client) {
		tag_read_free(read);
		return;
	}

	nfcd_interface_tag_call_get_all3(read->tag, read->cancellable,
	                                 tag_get_all_ready, read);
}

static void tag_read_start(struct nfcd_client *client, const char *path)
{
	struct tag_read *read;

	read = g_new0(struct tag_read, 1);
	read->client = client;
	read->path = g_strdup(path);
	read->cancellable = g_cancellable_new();

	client->reading = read;

	nfcd_interface_tag_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                     NFCD_DAEMON_SERVICE, path,
	                                     read->cancellable, tag_proxy_ready, read);
}

/*
 * Passport/eID BAC read. Unlike tag_read (which backs a polling cache no
 * single caller blocks on), this backs one direct readPassport() call, so
 * every exit path below calls back rather than silently orphaning - see
 * passport_read_finish(). Sequence: SELECT eMRTD app, GET CHALLENGE,
 * MUTUAL AUTHENTICATE, then EF.DG1 under secure messaging (SELECT + one or
 * more READ BINARY). At most one outstanding Transceive() at a time.
 */

#define PASSPORT_EMRTD_FID_HI	0x01
#define PASSPORT_EMRTD_FID_LO	0x01
#define PASSPORT_DG1_MAX_LEN	2048	/* generous sanity ceiling, not a real limit */

/* Same AID bac_build_select_aid() sends in the clear for BAC - PACE needs
 * its own copy since this one goes out under secure messaging instead,
 * after PACE's handshake (see pace_mutual_auth_ready()). */
static const guint8 pace_emrtd_aid[] = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

/* EF.CardAccess's well-known FID (ICAO 9303-11 4.1) - readable
 * unauthenticated, at the MF, before PACE's MSE:Set AT. */
static const guint8 ef_cardaccess_fid[] = { 0x01, 0x1C };
#define EF_CARDACCESS_MAX_LEN	2048	/* generous sanity ceiling, not a real limit */

static void passport_dg1_read_more(struct passport_read *read);

static void passport_read_free(struct passport_read *read)
{
	if (!read)
		return;

	if (read->tag)
		g_object_unref(read->tag);

	if (read->cancellable)
		g_object_unref(read->cancellable);

	if (read->dg1)
		g_byte_array_free(read->dg1, TRUE);

	if (read->pace_k)
		g_byte_array_free(read->pace_k, TRUE);

	if (read->card_access)
		g_byte_array_free(read->card_access, TRUE);

	if (read->pace)
		pace_exchange_free(read->pace);

	memset(&read->keys, 0, sizeof(read->keys));
	memset(&read->session, 0, sizeof(read->session));
	memset(&read->pace_session, 0, sizeof(read->pace_session));
	g_free(read);
}

/* The only place that invokes the caller's callback - every step below
 * ends here exactly once, success or failure. */
static void passport_read_finish(struct passport_read *read, gboolean success,
                                 const char *error_text, const char *mrz_text)
{
	nfcd_passport_cb cb = read->cb;
	void *user_data = read->user_data;

	if (read->client && read->client->passport_reading == read)
		read->client->passport_reading = NULL;

	passport_read_free(read);

	if (cb)
		cb(success, error_text, mrz_text, user_data);
}

/* Detaches from a client that's going away (torn down, or the tag in the
 * field changed) - the in-flight Transceive() still completes normally
 * (cancelled), and that callback is what actually calls passport_read_finish(). */
static void passport_read_abort(struct passport_read *read)
{
	if (!read)
		return;

	read->client = NULL;
	g_cancellable_cancel(read->cancellable);
}

/* A raw (pre-secure-messaging) APDU response: expect_data_len bytes of
 * data followed by SW1SW2 = 90 00. *data_out points into resp itself. */
static gboolean passport_raw_response_ok(const guint8 *resp, gsize len, gsize expect_data_len,
                                         const guint8 **data_out)
{
	if (len != expect_data_len + 2)
		return FALSE;
	if (resp[len - 2] != 0x90 || resp[len - 1] != 0x00)
		return FALSE;
	if (data_out)
		*data_out = resp;
	return TRUE;
}

static void passport_transceive(struct passport_read *read, GByteArray *apdu,
                                GAsyncReadyCallback callback)
{
	GVariant *data = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, apdu->data, apdu->len, 1);

	nfcd_interface_tag_call_transceive(read->tag, data, read->cancellable, callback, read);
	g_byte_array_free(apdu, TRUE);
}

static void passport_tag_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;

	read->tag = nfcd_interface_tag_proxy_new_for_bus_finish(res, &error);

	if (!read->tag) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	/* PACE runs against the MF (no app selected yet) - the eMRTD app
	 * isn't SELECTed until after secure messaging is up (see
	 * pace_mutual_auth_ready()). BAC selects it up front, in the clear.
	 * PACE also needs EF.CardAccess read first, to learn which OID/curve
	 * this document actually wants (see passport_select_ef_cardaccess_ready())
	 * rather than guessing - MSE:Set AT follows once that's known. */
	if (read->use_pace) {
		GByteArray *apdu = g_byte_array_new();
		guint8 header[] = { 0x00, 0xA4, 0x02, 0x0C, (guint8) sizeof(ef_cardaccess_fid) };

		g_byte_array_append(apdu, header, sizeof(header));
		g_byte_array_append(apdu, ef_cardaccess_fid, sizeof(ef_cardaccess_fid));
		passport_transceive(read, apdu, passport_select_ef_cardaccess_ready);
	}
	else
		passport_transceive(read, bac_build_select_aid(), passport_select_aid_ready);
}

static void passport_select_aid_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *apdu;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);

		if (!passport_raw_response_ok(bytes, len, 0, NULL)) {
			g_variant_unref(response);
			passport_read_finish(read, FALSE,
				"Not an ICAO 9303 document (eMRTD application not found)", NULL);
			return;
		}
		g_variant_unref(response);
	}

	apdu = bac_build_get_challenge();
	passport_transceive(read, apdu, passport_get_challenge_ready);
}

static void passport_get_challenge_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *apdu;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		const guint8 *data;

		if (!passport_raw_response_ok(bytes, len, 8, &data)) {
			g_variant_unref(response);
			passport_read_finish(read, FALSE, "GET CHALLENGE failed", NULL);
			return;
		}
		memcpy(read->rnd_icc, data, 8);
		g_variant_unref(response);
	}

	apdu = bac_build_mutual_authenticate(&read->keys, read->rnd_icc, &read->challenge);
	if (!apdu) {
		passport_read_finish(read, FALSE, "Failed to generate a random challenge", NULL);
		return;
	}
	passport_transceive(read, apdu, passport_mutual_auth_ready);
}

static void passport_mutual_auth_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *apdu;
	guint8 fid[2] = { PASSPORT_EMRTD_FID_HI, PASSPORT_EMRTD_FID_LO };

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		const guint8 *data;

		if (!passport_raw_response_ok(bytes, len, 40, &data)) {
			g_variant_unref(response);
			passport_read_finish(read, FALSE,
				"BAC authentication rejected - check the document number, date "
				"of birth and date of expiry, or this document may need PACE "
				"instead of BAC", NULL);
			return;
		}

		if (!bac_process_mutual_authenticate_response(&read->keys, &read->challenge,
		                                              read->rnd_icc, data, 40,
		                                              &read->session)) {
			g_variant_unref(response);
			passport_read_finish(read, FALSE,
				"BAC authentication response could not be verified", NULL);
			return;
		}
		g_variant_unref(response);
	}

	apdu = bac_sm_protect(&read->session, 0x00, 0xA4, 0x02, 0x0C, fid, sizeof(fid), -1);
	if (!apdu) {
		passport_read_finish(read, FALSE, "Failed to build the secure messaging command", NULL);
		return;
	}
	passport_transceive(read, apdu, passport_select_dg1_ready);
}

/* ---- PACE: SELECT + read EF.CardAccess (unauthenticated - see pace.h),
 * pick a PACEInfo entry this build can actually run, then MSE:Set AT and
 * General Authenticate rounds 1-4 (see pace.h), then SELECT eMRTD app
 * under the now-established secure messaging (unlike BAC, which selects
 * it in the clear up front). Once pace_select_aid_ready() succeeds, the
 * flow rejoins BAC's at passport_select_dg1_ready() - both paths land on
 * the same DG1 read loop, just with passport_sm_response_ok() dispatching
 * to pace_sm_* instead of bac_sm_* (see read->use_pace there). ---- */

static void passport_select_ef_cardaccess_ready(GObject *source, GAsyncResult *res,
                                                gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *apdu;
	guint8 cmd[] = { 0x00, 0xB0, 0x00, 0x00, 0x00 };	/* Le=0 -> up to 256 bytes */

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean sel_ok = passport_raw_response_ok(bytes, len, 0, NULL);

		g_variant_unref(response);
		if (!sel_ok) {
			passport_read_finish(read, FALSE,
				"Could not select EF.CardAccess - this document doesn't "
				"expose its PACE parameters where expected", NULL);
			return;
		}
	}

	read->card_access = g_byte_array_new();
	apdu = g_byte_array_new();
	g_byte_array_append(apdu, cmd, sizeof(cmd));
	passport_transceive(read, apdu, passport_ef_cardaccess_rest_ready);
}

/* Picks a PACEInfo entry this build can run out of everything
 * pace_parse_card_access() found, sets up read->pace on success. Returns
 * NULL on success; otherwise a caller-owned (g_free()) error string
 * identifying exactly what was found, if anything. */
static gchar *passport_pick_pace_entry(struct passport_read *read)
{
	PaceInfoEntry entries[8];
	gsize count = pace_parse_card_access(read->card_access->data, read->card_access->len,
	                                     entries, G_N_ELEMENTS(entries));
	gsize i;

	for (i = 0; i < count; i++) {
		int curve_nid;

		if (!pace_oid_supported(entries[i].oid, entries[i].oid_len))
			continue;
		curve_nid = pace_ec_curve_for_parameter_id(entries[i].parameter_id);
		if (curve_nid == 0)
			continue;

		read->pace = pace_exchange_new(read->pace_k, curve_nid);
		g_byte_array_free(read->pace_k, TRUE);
		read->pace_k = NULL;
		if (!read->pace)
			return g_strdup("Failed to set up the PACE exchange");

		memcpy(read->pace_selected_oid, entries[i].oid, entries[i].oid_len);
		read->pace_selected_oid_len = entries[i].oid_len;
		return NULL;
	}

	if (count == 0)
		return g_strdup("This document's EF.CardAccess didn't list any PACE "
		                "support (SecurityInfos empty or unparseable)");

	/* Name exactly what was found and rejected, e.g. "protocol=...
	 * parameterId=192" - so a real rejection here is a precise
	 * diagnostic, not another guessing round. */
	{
		GString *msg = g_string_new(
			"This document's PACEInfo doesn't match anything this build "
			"supports (only ECDH-GM-AES-128 on NIST P-256 or "
			"brainpoolP256r1 - see pace.h). Found: ");

		for (i = 0; i < count; i++) {
			gsize j;

			if (i > 0)
				g_string_append(msg, "; ");
			g_string_append(msg, "protocol=");
			for (j = 0; j < entries[i].oid_len; j++)
				g_string_append_printf(msg, "%02X", entries[i].oid[j]);
			if (entries[i].parameter_id >= 0)
				g_string_append_printf(msg, " parameterId=%d",
					entries[i].parameter_id);
		}
		return g_string_free(msg, FALSE);
	}
}

static void passport_ef_cardaccess_rest_ready(GObject *source, GAsyncResult *res,
                                              gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean sw_ok = len >= 2 && bytes[len - 2] == 0x90 && bytes[len - 1] == 0x00;

		if (!sw_ok || len < 3) {
			g_variant_unref(response);
			passport_read_finish(read, FALSE,
				"Failed to read EF.CardAccess", NULL);
			return;
		}
		g_byte_array_append(read->card_access, bytes, len - 2);
		g_variant_unref(response);
	}

	if (read->card_access_total_len == 0) {
		gsize header_len, content_len;

		if (!bac_ber_tlv_header(read->card_access->data, read->card_access->len,
		                        &header_len, &content_len) ||
		    header_len + content_len > EF_CARDACCESS_MAX_LEN) {
			passport_read_finish(read, FALSE,
				"EF.CardAccess has an unexpected structure", NULL);
			return;
		}
		read->card_access_total_len = header_len + content_len;
	}

	if (read->card_access->len < read->card_access_total_len) {
		GByteArray *apdu = g_byte_array_new();
		guint offset = (guint) read->card_access->len;
		gsize remaining = read->card_access_total_len - read->card_access->len;
		guint8 cmd[] = { 0x00, 0xB0, (guint8)(offset >> 8), (guint8)(offset & 0xFF),
		                (guint8) MIN(remaining, 255) };

		g_byte_array_append(apdu, cmd, sizeof(cmd));
		passport_transceive(read, apdu, passport_ef_cardaccess_rest_ready);
		return;
	}

	{
		gchar *err = passport_pick_pace_entry(read);
		GByteArray *apdu;

		if (err) {
			/* passport_read_finish() calls cb() synchronously and it
			 * copies error_text before returning - safe to free after. */
			passport_read_finish(read, FALSE, err, NULL);
			g_free(err);
			return;
		}
		apdu = pace_build_mse_set_at(read->pace_selected_oid,
		                             read->pace_selected_oid_len, TRUE);
		passport_transceive(read, apdu, pace_mse_set_at_ready);
	}
}

static void pace_mse_set_at_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean set_ok = passport_raw_response_ok(bytes, len, 0, NULL);

		g_variant_unref(response);
		if (!set_ok) {
			/* Unexpected: EF.CardAccess just said this OID/curve is
			 * exactly what the document wants (see
			 * passport_pick_pace_entry()) - a rejection here means
			 * something other than a wrong-parameter guess. */
			passport_read_finish(read, FALSE,
				"MSE:Set AT was rejected even with this document's own "
				"advertised PACE parameters", NULL);
			return;
		}
	}

	passport_transceive(read, pace_build_get_nonce(), pace_get_nonce_ready);
}

static void pace_get_nonce_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean nonce_ok = pace_process_nonce_response(read->pace, bytes, len);

		g_variant_unref(response);
		if (!nonce_ok) {
			passport_read_finish(read, FALSE,
				"Failed to decrypt PACE's nonce - the CAN is probably wrong",
				NULL);
			return;
		}
	}

	{
		GByteArray *apdu = pace_build_map_nonce(read->pace);

		if (!apdu) {
			passport_read_finish(read, FALSE, "Failed to generate a mapping key", NULL);
			return;
		}
		passport_transceive(read, apdu, pace_map_nonce_ready);
	}
}

static void pace_map_nonce_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean map_ok = pace_process_map_nonce_response(read->pace, bytes, len);

		g_variant_unref(response);
		if (!map_ok) {
			passport_read_finish(read, FALSE, "Failed to map PACE's nonce", NULL);
			return;
		}
	}

	{
		GByteArray *apdu = pace_build_key_agreement(read->pace);

		if (!apdu) {
			passport_read_finish(read, FALSE, "Failed to generate a key-agreement key",
			                     NULL);
			return;
		}
		passport_transceive(read, apdu, pace_key_agreement_ready);
	}
}

static void pace_key_agreement_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean ka_ok = pace_process_key_agreement_response(read->pace, bytes, len,
		                                                     &read->pace_session);

		g_variant_unref(response);
		if (!ka_ok) {
			passport_read_finish(read, FALSE, "PACE key agreement failed", NULL);
			return;
		}
	}

	{
		GByteArray *apdu = pace_build_mutual_auth(read->pace);

		if (!apdu) {
			passport_read_finish(read, FALSE, "Failed to build the PACE authentication "
			                     "token", NULL);
			return;
		}
		passport_transceive(read, apdu, pace_mutual_auth_ready);
	}
}

static void pace_mutual_auth_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *apdu;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
		gboolean auth_ok = pace_verify_mutual_auth_response(read->pace, bytes, len);

		g_variant_unref(response);
		if (!auth_ok) {
			passport_read_finish(read, FALSE,
				"PACE authentication rejected - check the CAN", NULL);
			return;
		}
	}

	/* Secure messaging is live; read->pace (the ephemeral EC state) has
	 * done its job - read->pace_session carries everything needed from
	 * here on. Free it now rather than at passport_read_free() so the
	 * OpenSSL EC/BN state doesn't outlive the handshake it was for. */
	pace_exchange_free(read->pace);
	read->pace = NULL;

	apdu = pace_sm_protect(&read->pace_session, 0x00, 0xA4, 0x04, 0x0C,
	                       pace_emrtd_aid, sizeof(pace_emrtd_aid), -1);
	if (!apdu) {
		passport_read_finish(read, FALSE, "Failed to build the secure messaging command", NULL);
		return;
	}
	passport_transceive(read, apdu, pace_select_aid_ready);
}

static void pace_select_aid_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *plaintext = NULL;
	guint16 sw = 0;
	guint8 fid[2] = { PASSPORT_EMRTD_FID_HI, PASSPORT_EMRTD_FID_LO };
	GByteArray *apdu;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	{
		gsize len = 0;
		const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);

		ok = pace_sm_unprotect(&read->pace_session, bytes, len, &plaintext, &sw);
		g_variant_unref(response);
	}
	if (plaintext)
		g_byte_array_free(plaintext, TRUE); /* SELECT returns no data */

	if (!ok || sw != 0x9000) {
		passport_read_finish(read, FALSE,
			"Failed to select the eMRTD application under secure messaging", NULL);
		return;
	}

	apdu = pace_sm_protect(&read->pace_session, 0x00, 0xA4, 0x02, 0x0C, fid, sizeof(fid), -1);
	if (!apdu) {
		passport_read_finish(read, FALSE, "Failed to build the secure messaging command", NULL);
		return;
	}
	/* Rejoins the BAC path from here - same DG1 read loop either way. */
	passport_transceive(read, apdu, passport_select_dg1_ready);
}

/* Common to every step after MUTUAL AUTHENTICATE: unwrap the response,
 * fail on a MAC mismatch or a non-9000 status. *plaintext_out is NULL when
 * ok is TRUE and the step had no data to return (e.g. after SELECT). */
static gboolean passport_sm_response_ok(struct passport_read *read, GVariant *response,
                                        GByteArray **plaintext_out, const char **error_out)
{
	gsize len = 0;
	const guint8 *bytes = g_variant_get_fixed_array(response, &len, 1);
	guint16 sw = 0;
	gboolean ok;

	*plaintext_out = NULL;

	if (read->use_pace)
		ok = pace_sm_unprotect(&read->pace_session, bytes, len, plaintext_out, &sw);
	else
		ok = bac_sm_unprotect(&read->session, bytes, len, plaintext_out, &sw);
	if (!ok) {
		*error_out = "Secure messaging integrity check failed";
		return FALSE;
	}
	if (sw != 0x9000) {
		if (*plaintext_out)
			g_byte_array_free(*plaintext_out, TRUE);
		*plaintext_out = NULL;
		*error_out = "The document rejected a secure messaging command";
		return FALSE;
	}
	return TRUE;
}

static void passport_select_dg1_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *plaintext = NULL;
	const char *error_text = NULL;
	GByteArray *apdu;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	ok = passport_sm_response_ok(read, response, &plaintext, &error_text);
	g_variant_unref(response);
	if (plaintext)
		g_byte_array_free(plaintext, TRUE); /* SELECT returns no data */

	if (!ok) {
		passport_read_finish(read, FALSE,
			error_text ? error_text :
			"Failed to select the MRZ data group (EF.DG1) - this document "
			"may not support BAC reading of DG1", NULL);
		return;
	}

	read->dg1 = g_byte_array_new();
	apdu = read->use_pace ?
	      pace_sm_protect(&read->pace_session, 0x00, 0xB0, 0x00, 0x00, NULL, 0, 4) :
	      bac_sm_protect(&read->session, 0x00, 0xB0, 0x00, 0x00, NULL, 0, 4);
	if (!apdu) {
		passport_read_finish(read, FALSE, "Failed to build the secure messaging command", NULL);
		return;
	}
	passport_transceive(read, apdu, passport_dg1_rest_ready);
}

static void passport_dg1_rest_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct passport_read *read = user_data;
	GError *error = NULL;
	GVariant *response = NULL;
	gboolean ok;
	GByteArray *plaintext = NULL;
	const char *error_text = NULL;

	ok = nfcd_interface_tag_call_transceive_finish(NFCD_INTERFACE_TAG(source),
	                                               &response, res, &error);
	if (!ok) {
		g_error_free(error);
		passport_read_finish(read, FALSE, "Failed to reach the tag", NULL);
		return;
	}

	ok = passport_sm_response_ok(read, response, &plaintext, &error_text);
	g_variant_unref(response);

	if (!ok || !plaintext) {
		if (plaintext)
			g_byte_array_free(plaintext, TRUE);
		passport_read_finish(read, FALSE,
			error_text ? error_text : "Failed to read the MRZ data group (EF.DG1)", NULL);
		return;
	}

	g_byte_array_append(read->dg1, plaintext->data, plaintext->len);
	g_byte_array_free(plaintext, TRUE);

	if (read->dg1_total_len == 0) {
		/* This was the first chunk - now enough header is in hand to know
		 * the file's real length. */
		gsize header_len, content_len;

		if (!bac_ber_tlv_header(read->dg1->data, read->dg1->len, &header_len, &content_len) ||
		    header_len + content_len > PASSPORT_DG1_MAX_LEN) {
			passport_read_finish(read, FALSE,
				"The MRZ data group (EF.DG1) has an unexpected structure", NULL);
			return;
		}
		read->dg1_total_len = header_len + content_len;
	}

	passport_dg1_read_more(read);
}

static void passport_dg1_read_more(struct passport_read *read)
{
	gsize remaining = read->dg1_total_len - read->dg1->len;
	gsize chunk;
	guint offset;
	GByteArray *apdu;
	gchar *mrz;

	if (remaining == 0) {
		mrz = bac_parse_dg1_mrz(read->dg1->data, read->dg1->len);
		if (!mrz) {
			passport_read_finish(read, FALSE,
				"Could not parse the MRZ data group (EF.DG1)", NULL);
			return;
		}
		passport_read_finish(read, TRUE, NULL, mrz);
		g_free(mrz);
		return;
	}

	chunk = MIN(remaining, 255);
	offset = (guint) read->dg1->len;

	apdu = read->use_pace ?
	      pace_sm_protect(&read->pace_session, 0x00, 0xB0, (guint8)(offset >> 8),
	                      (guint8)(offset & 0xFF), NULL, 0, (gint) chunk) :
	      bac_sm_protect(&read->session, 0x00, 0xB0, (guint8)(offset >> 8),
	                      (guint8)(offset & 0xFF), NULL, 0, (gint) chunk);
	if (!apdu) {
		passport_read_finish(read, FALSE, "Failed to build the secure messaging command", NULL);
		return;
	}
	passport_transceive(read, apdu, passport_dg1_rest_ready);
}

/* Common preconditions for either a BAC or a PACE read: one at a time, a
 * tag in the field, and it has to be ISO-DEP (both protocols run over
 * APDUs). Returns FALSE (and has already called cb) if any fails. */
static gboolean passport_read_precheck(struct nfcd_client *client, nfcd_passport_cb cb,
                                       void *user_data)
{
	if (client->passport_reading) {
		cb(FALSE, "A passport read is already in progress", NULL, user_data);
		return FALSE;
	}
	if (!client->tag_path) {
		cb(FALSE, "No tag in the field", NULL, user_data);
		return FALSE;
	}
	if (client->tag_protocol != NFC_PROTOCOL_T4A && client->tag_protocol != NFC_PROTOCOL_T4B) {
		cb(FALSE, "Not an ISO-DEP tag - passports and eIDs need ISO-DEP (t4a/t4b)",
		  NULL, user_data);
		return FALSE;
	}
	return TRUE;
}

static void passport_read_dispatch(struct nfcd_client *client, struct passport_read *read,
                                   nfcd_passport_cb cb, void *user_data)
{
	read->client = client;
	read->cancellable = g_cancellable_new();
	read->cb = cb;
	read->user_data = user_data;

	client->passport_reading = read;

	nfcd_interface_tag_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                     NFCD_DAEMON_SERVICE, client->tag_path,
	                                     read->cancellable, passport_tag_proxy_ready, read);
}

void nfcd_client_read_passport(struct nfcd_client *client, const char *document_number,
                               const char *date_of_birth, const char *date_of_expiry,
                               nfcd_passport_cb cb, void *user_data)
{
	struct passport_read *read;
	BacStaticKeys keys;

	if (!passport_read_precheck(client, cb, user_data))
		return;

	if (!bac_derive_static_keys(document_number, date_of_birth, date_of_expiry, &keys)) {
		cb(FALSE, "Expected documentNumber, dateOfBirth and dateOfExpiry (YYMMDD)",
		  NULL, user_data);
		return;
	}

	read = g_new0(struct passport_read, 1);
	read->keys = keys;
	passport_read_dispatch(client, read, cb, user_data);
}

void nfcd_client_read_passport_pace(struct nfcd_client *client, const char *can,
                                    nfcd_passport_cb cb, void *user_data)
{
	struct passport_read *read;
	GByteArray *k;

	if (!passport_read_precheck(client, cb, user_data))
		return;

	k = pace_derive_k_can(can);
	if (!k) {
		cb(FALSE, "Expected can (the Card Access Number printed on the document)",
		  NULL, user_data);
		return;
	}

	/* The actual PaceExchange (which needs a curve) isn't set up until
	 * EF.CardAccess says which one this document wants - see
	 * passport_pick_pace_entry(). k is kept until then. */
	read = g_new0(struct passport_read, 1);
	read->use_pace = TRUE;
	read->pace_k = k;
	passport_read_dispatch(client, read, cb, user_data);
}

static void set_current_tag(struct nfcd_client *client, const char *path)
{
	if (!g_strcmp0(client->tag_path, path))
		return;

	if (client->reading) {
		tag_read_abort(client->reading);
		client->reading = NULL;
	}

	if (client->passport_reading) {
		passport_read_abort(client->passport_reading);
		client->passport_reading = NULL;
	}

	g_free(client->tag_path);
	client->tag_path = g_strdup(path);
	client->tag_is_type2 = FALSE;
	client->tag_protocol = 0;

	if (client->tag_json) {
		j_release(&client->tag_json);
		client->tag_json = NULL;
	}

	if (!path) {
		notify_tag(client);
		return;
	}

	/* Tell subscribers a tag arrived straight away; the decoded contents
	 * follow in a second update once the read completes. */
	notify_tag(client);

	tag_read_start(client, path);
}

static void update_tags(struct nfcd_client *client, const gchar *const *tags)
{
	set_current_tag(client, (tags && tags[0]) ? tags[0] : NULL);
}

/*
 * Adapter
 */

static void adapter_enabled_changed(NfcdInterfaceAdapter *adapter, gboolean enabled,
                                    gpointer user_data)
{
	struct nfcd_client *client = user_data;

	client->adapter_enabled = enabled;
	notify_state(client);
}

static void adapter_powered_changed(NfcdInterfaceAdapter *adapter, gboolean powered,
                                    gpointer user_data)
{
	struct nfcd_client *client = user_data;

	client->powered = powered;
	notify_state(client);
}

static void adapter_mode_changed(NfcdInterfaceAdapter *adapter, guint mode,
                                 gpointer user_data)
{
	struct nfcd_client *client = user_data;

	client->mode = mode;
	notify_state(client);
}

static void adapter_present_changed(NfcdInterfaceAdapter *adapter, gboolean present,
                                    gpointer user_data)
{
	struct nfcd_client *client = user_data;

	client->present = present;
	notify_state(client);
}

static void adapter_tags_changed(NfcdInterfaceAdapter *adapter,
                                 const gchar *const *tags, gpointer user_data)
{
	struct nfcd_client *client = user_data;

	update_tags(client, tags);
}

static void adapter_get_all_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	NfcdInterfaceAdapter *adapter = NFCD_INTERFACE_ADAPTER(source);
	GError *error = NULL;
	gint version = 0;
	gboolean enabled = FALSE, powered = FALSE, present = FALSE;
	guint supported_modes = 0, mode = 0, supported_techs = 0;
	gchar **tags = NULL, **peers = NULL, **hosts = NULL;
	GVariant *params = NULL;

	if (!nfcd_interface_adapter_call_get_all4_finish(adapter, &version, &enabled,
	                                                 &powered, &supported_modes,
	                                                 &mode, &present, &tags, &peers,
	                                                 &hosts, &supported_techs,
	                                                 &params, res, &error)) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to query adapter state: %s", error->message);
		g_error_free(error);
		return;
	}

	client->adapter_enabled = enabled;
	client->powered = powered;
	client->supported_modes = supported_modes;
	client->mode = mode;
	client->present = present;
	client->techs = supported_techs;
	client->available = TRUE;

	notify_state(client);

	update_tags(client, (const gchar *const *) tags);

	g_strfreev(tags);
	g_strfreev(peers);
	g_strfreev(hosts);
	g_variant_unref(params);
}

static void adapter_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	GError *error = NULL;
	NfcdInterfaceAdapter *adapter;

	adapter = nfcd_interface_adapter_proxy_new_for_bus_finish(res, &error);

	if (!adapter) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to create adapter proxy: %s", error->message);
		g_error_free(error);
		return;
	}

	if (client->adapter)
		g_object_unref(client->adapter);

	client->adapter = adapter;

	g_signal_connect(adapter, "enabled-changed",
	                 G_CALLBACK(adapter_enabled_changed), client);
	g_signal_connect(adapter, "powered-changed",
	                 G_CALLBACK(adapter_powered_changed), client);
	g_signal_connect(adapter, "mode-changed",
	                 G_CALLBACK(adapter_mode_changed), client);
	g_signal_connect(adapter, "target-present-changed",
	                 G_CALLBACK(adapter_present_changed), client);
	g_signal_connect(adapter, "tags-changed",
	                 G_CALLBACK(adapter_tags_changed), client);

	nfcd_interface_adapter_call_get_all4(adapter, client->cancellable,
	                                     adapter_get_all_ready, client);
}

static void attach_adapter(struct nfcd_client *client, const char *path)
{
	if (!path) {
		if (client->adapter) {
			g_object_unref(client->adapter);
			client->adapter = NULL;
		}

		g_free(client->adapter_path);
		client->adapter_path = NULL;
		client->available = FALSE;

		set_current_tag(client, NULL);
		notify_state(client);
		return;
	}

	if (!g_strcmp0(client->adapter_path, path))
		return;

	g_free(client->adapter_path);
	client->adapter_path = g_strdup(path);

	nfcd_interface_adapter_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                         NFCD_DAEMON_SERVICE, path,
	                                         client->cancellable,
	                                         adapter_proxy_ready, client);
}

/*
 * Daemon
 */

static void daemon_adapters_changed(NfcdInterfaceDaemon *daemon,
                                    const gchar *const *adapters, gpointer user_data)
{
	struct nfcd_client *client = user_data;

	attach_adapter(client, (adapters && adapters[0]) ? adapters[0] : NULL);
}

static void daemon_get_all_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	NfcdInterfaceDaemon *daemon = NFCD_INTERFACE_DAEMON(source);
	GError *error = NULL;
	gint version = 0, daemon_version = 0;
	gchar **adapters = NULL;
	guint mode = 0, techs = 0;

	if (!nfcd_interface_daemon_call_get_all4_finish(daemon, &version, &adapters,
	                                                &daemon_version, &mode, &techs,
	                                                res, &error)) {
		/* GetAll4 arrived in nfcd 1.2.0; an older daemon means we can't
		 * drive it and it's better to say so loudly than to half work. */
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to query nfcd (needs nfcd >= 1.2.0): %s", error->message);
		g_error_free(error);
		return;
	}

	client->daemon_version = daemon_version;

	attach_adapter(client, (adapters && adapters[0]) ? adapters[0] : NULL);

	g_strfreev(adapters);
}

static void request_reader_writer_mode_ready(GObject *source, GAsyncResult *res,
                                             gpointer user_data)
{
	struct nfcd_client *client = user_data;
	NfcdInterfaceDaemon *daemon = NFCD_INTERFACE_DAEMON(source);
	GError *error = NULL;
	guint id = 0;

	if (nfcd_interface_daemon_call_request_mode_finish(daemon, &id, res, &error)) {
		client->mode_request_id = id;
	} else {
		/* Reading and writing tags just won't work until nfcd is restarted
		 * or this client reconnects, so this is worth more than a debug
		 * line, but it's not fatal: getStatus/getTagInfo etc. still work. */
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to request reader/writer mode: %s", error->message);
		g_error_free(error);
	}
}

static void daemon_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	GError *error = NULL;
	NfcdInterfaceDaemon *daemon;

	daemon = nfcd_interface_daemon_proxy_new_for_bus_finish(res, &error);

	if (!daemon) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to create nfcd proxy: %s", error->message);
		g_error_free(error);
		return;
	}

	if (client->daemon)
		g_object_unref(client->daemon);

	client->daemon = daemon;
	client->mode_request_id = 0;

	g_signal_connect(daemon, "adapters-changed",
	                 G_CALLBACK(daemon_adapters_changed), client);

	nfcd_interface_daemon_call_get_all4(daemon, client->cancellable,
	                                    daemon_get_all_ready, client);

	/*
	 * nfcd starts every adapter with mode 0 (nothing polling) and expects a
	 * client to ask for a mode: on Sailfish that's their screen-state aware
	 * NFC middleware, which LuneOS has no equivalent of. Tools like ndef-read
	 * only listen for tags-changed, they never request a mode themselves, so
	 * without this nothing would ever be detected. Hold reader/writer for as
	 * long as we're connected to the daemon; nfcd's own enabled setting
	 * remains the real on/off switch.
	 */
	nfcd_interface_daemon_call_request_mode(daemon, NFCD_MODE_READER_WRITER, 0,
	                                        client->cancellable,
	                                        request_reader_writer_mode_ready, client);
}

static void daemon_appeared(GDBusConnection *connection, const gchar *name,
                            const gchar *name_owner, gpointer user_data)
{
	struct nfcd_client *client = user_data;

	g_message("nfcd appeared on the bus");

	nfcd_interface_daemon_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                        NFCD_DAEMON_SERVICE, NFCD_ROOT_PATH,
	                                        client->cancellable,
	                                        daemon_proxy_ready, client);
}

static void daemon_vanished(GDBusConnection *connection, const gchar *name,
                            gpointer user_data)
{
	struct nfcd_client *client = user_data;

	g_message("nfcd disappeared from the bus");

	if (client->daemon) {
		g_object_unref(client->daemon);
		client->daemon = NULL;
	}

	client->daemon_version = 0;
	client->mode_request_id = 0;

	attach_adapter(client, NULL);
}

/*
 * Settings
 */

static void settings_enabled_changed(NfcdInterfaceSettings *settings, gboolean enabled,
                                     gpointer user_data)
{
	struct nfcd_client *client = user_data;

	client->settings_valid = TRUE;
	client->settings_enabled = enabled;
	notify_state(client);
}

static void settings_get_all_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	NfcdInterfaceSettings *settings = NFCD_INTERFACE_SETTINGS(source);
	GError *error = NULL;
	gint version = 0;
	gboolean enabled = FALSE;

	if (!nfcd_interface_settings_call_get_all_finish(settings, &version, &enabled,
	                                                 res, &error)) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to query nfcd settings: %s", error->message);
		g_error_free(error);
		return;
	}

	client->settings_valid = TRUE;
	client->settings_enabled = enabled;

	notify_state(client);
}

static void settings_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	GError *error = NULL;
	NfcdInterfaceSettings *settings;

	settings = nfcd_interface_settings_proxy_new_for_bus_finish(res, &error);

	if (!settings) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to create nfcd settings proxy: %s", error->message);
		g_error_free(error);
		return;
	}

	if (client->settings)
		g_object_unref(client->settings);

	client->settings = settings;

	g_signal_connect(settings, "enabled-changed",
	                 G_CALLBACK(settings_enabled_changed), client);

	nfcd_interface_settings_call_get_all(settings, client->cancellable,
	                                     settings_get_all_ready, client);
}

static void settings_appeared(GDBusConnection *connection, const gchar *name,
                              const gchar *name_owner, gpointer user_data)
{
	struct nfcd_client *client = user_data;

	nfcd_interface_settings_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                          NFCD_SETTINGS_SERVICE, NFCD_ROOT_PATH,
	                                          client->cancellable,
	                                          settings_proxy_ready, client);
}

static void settings_vanished(GDBusConnection *connection, const gchar *name,
                              gpointer user_data)
{
	struct nfcd_client *client = user_data;

	if (client->settings) {
		g_object_unref(client->settings);
		client->settings = NULL;
	}

	client->settings_valid = FALSE;

	notify_state(client);
}

/*
 * Public interface
 */

struct nfcd_client *nfcd_client_create(nfcd_state_cb state_cb, nfcd_tag_cb tag_cb,
                                       nfcd_hce_cb hce_cb, void *user_data)
{
	struct nfcd_client *client;

	client = g_new0(struct nfcd_client, 1);
	client->state_cb = state_cb;
	client->tag_cb = tag_cb;
	client->hce_cb = hce_cb;
	client->user_data = user_data;
	client->cancellable = g_cancellable_new();
	client->mifare_key_cache = g_hash_table_new_full(g_str_hash, g_str_equal,
	                                                 g_free, g_free);

	client->daemon_watch = g_bus_watch_name(G_BUS_TYPE_SYSTEM, NFCD_DAEMON_SERVICE,
	                                        G_BUS_NAME_WATCHER_FLAGS_NONE,
	                                        daemon_appeared, daemon_vanished,
	                                        client, NULL);

	client->settings_watch = g_bus_watch_name(G_BUS_TYPE_SYSTEM, NFCD_SETTINGS_SERVICE,
	                                          G_BUS_NAME_WATCHER_FLAGS_NONE,
	                                          settings_appeared, settings_vanished,
	                                          client, NULL);

	return client;
}

void nfcd_client_free(struct nfcd_client *client)
{
	if (!client)
		return;

	g_cancellable_cancel(client->cancellable);

	if (client->reading) {
		tag_read_abort(client->reading);
		client->reading = NULL;
	}

	if (client->passport_reading) {
		passport_read_abort(client->passport_reading);
		client->passport_reading = NULL;
	}

	if (client->daemon_watch)
		g_bus_unwatch_name(client->daemon_watch);

	if (client->settings_watch)
		g_bus_unwatch_name(client->settings_watch);

	if (client->daemon)
		g_object_unref(client->daemon);

	if (client->adapter)
		g_object_unref(client->adapter);

	if (client->settings)
		g_object_unref(client->settings);

	if (client->tag_json)
		j_release(&client->tag_json);

	if (client->mifare_key_cache)
		g_hash_table_unref(client->mifare_key_cache);

	if (client->hce_profiles)
		g_hash_table_unref(client->hce_profiles);

	g_free(client->hce_event_aid_hex);

	g_object_unref(client->cancellable);
	g_free(client->adapter_path);
	g_free(client->tag_path);
	g_free(client);
}

/*
 * Card emulation. Each registered AID gets its own struct hce_profile,
 * with its own LocalHostApp skeleton exported at a distinct object path
 * and registered separately against nfcd - nfcd routes an incoming
 * SELECT by AID to whichever registration matches, so several profiles
 * can be active at once. Same AID-select/APDU-exchange model Android's
 * own HCE uses (HostApduService/CardEmulation - see
 * developer.android.com/develop/connectivity/nfc/hce). Process answers
 * differently depending on INS (SELECT vs a read-style request) but
 * still only ever returns one fixed payload per profile: this is a
 * personal-identifier/badge feature, not a general APDU responder.
 */

struct hce_profile {
	struct nfcd_client *client;
	gchar *aid_hex;
	gchar *object_path;
	NfcdInterfaceLocalHostApp *skeleton;
	GByteArray *payload;
	gboolean implicit;
	gboolean registered;
	guint next_response_id;
};

static gboolean hce_handle_start(NfcdInterfaceLocalHostApp *skeleton,
                                 GDBusMethodInvocation *invocation,
                                 const gchar *host, gpointer user_data)
{
	nfcd_interface_local_host_app_complete_start(skeleton, invocation);
	return TRUE;
}

static gboolean hce_handle_restart(NfcdInterfaceLocalHostApp *skeleton,
                                   GDBusMethodInvocation *invocation,
                                   const gchar *host, gpointer user_data)
{
	nfcd_interface_local_host_app_complete_restart(skeleton, invocation);
	return TRUE;
}

static gboolean hce_handle_stop(NfcdInterfaceLocalHostApp *skeleton,
                                GDBusMethodInvocation *invocation,
                                const gchar *path, gpointer user_data)
{
	nfcd_interface_local_host_app_complete_stop(skeleton, invocation);
	return TRUE;
}

static gboolean hce_handle_implicit_select(NfcdInterfaceLocalHostApp *skeleton,
                                           GDBusMethodInvocation *invocation,
                                           const gchar *host, gpointer user_data)
{
	nfcd_interface_local_host_app_complete_implicit_select(skeleton, invocation);
	return TRUE;
}

static gboolean hce_handle_select(NfcdInterfaceLocalHostApp *skeleton,
                                  GDBusMethodInvocation *invocation,
                                  const gchar *host, gpointer user_data)
{
	nfcd_interface_local_host_app_complete_select(skeleton, invocation);
	return TRUE;
}

static gboolean hce_handle_deselect(NfcdInterfaceLocalHostApp *skeleton,
                                    GDBusMethodInvocation *invocation,
                                    const gchar *path, gpointer user_data)
{
	nfcd_interface_local_host_app_complete_deselect(skeleton, invocation);
	return TRUE;
}

/* ISO 7816-4 instruction bytes we distinguish; anything else gets
 * "instruction not supported" rather than being treated as a read. */
#define HCE_INS_SELECT		0xA4
#define HCE_INS_READ_BINARY	0xB0
#define HCE_INS_GET_DATA	0xCA

static gboolean hce_handle_process(NfcdInterfaceLocalHostApp *skeleton,
                                   GDBusMethodInvocation *invocation,
                                   const gchar *host, guchar cla, guchar ins,
                                   guchar p1, guchar p2, GVariant *data,
                                   guint le, gpointer user_data)
{
	struct hce_profile *profile = user_data;
	GVariant *response;
	guchar sw1, sw2;
	guint response_id;

	switch (ins) {
	case HCE_INS_SELECT:
		/* Already routed to us by AID - just ack, no data to return. */
		response = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1);
		sw1 = 0x90;
		sw2 = 0x00;
		break;
	case HCE_INS_READ_BINARY:
	case HCE_INS_GET_DATA:
		response = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
			profile->payload->data, profile->payload->len, 1);
		sw1 = 0x90;
		sw2 = 0x00;
		break;
	default:
		response = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1);
		sw1 = 0x6D;
		sw2 = 0x00;
		break;
	}

	/* response_id 0 tells nfcd we don't want ResponseStatus - we do, so
	 * hand out a non-zero, per-profile id (0 is never used, wrap included). */
	response_id = ++profile->next_response_id;
	if (!response_id)
		response_id = ++profile->next_response_id;

	nfcd_interface_local_host_app_complete_process(skeleton, invocation,
		response, sw1, sw2, response_id);
	return TRUE;
}

static gboolean hce_handle_response_status(NfcdInterfaceLocalHostApp *skeleton,
                                           GDBusMethodInvocation *invocation,
                                           guint response_id, gboolean ok,
                                           gpointer user_data)
{
	struct hce_profile *profile = user_data;
	struct nfcd_client *client = profile->client;

	/* Record which AID a reader actually received a response for, so
	 * nfcd_client_get_hce_event() can surface real confirmation instead
	 * of firing blind. */
	g_free(client->hce_event_aid_hex);
	client->hce_event_aid_hex = g_strdup(profile->aid_hex);
	client->hce_event_ok = ok;

	if (client->hce_cb)
		client->hce_cb(client, client->user_data);

	nfcd_interface_local_host_app_complete_response_status(skeleton, invocation);
	return TRUE;
}

static gboolean hce_export_skeleton(struct hce_profile *profile)
{
	GDBusConnection *connection;
	GError *error = NULL;

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!connection) {
		g_warning("Failed to connect to system bus: %s", error->message);
		g_error_free(error);
		return FALSE;
	}

	profile->skeleton = nfcd_interface_local_host_app_skeleton_new();
	g_signal_connect(profile->skeleton, "handle-start",
	                 G_CALLBACK(hce_handle_start), profile);
	g_signal_connect(profile->skeleton, "handle-restart",
	                 G_CALLBACK(hce_handle_restart), profile);
	g_signal_connect(profile->skeleton, "handle-stop",
	                 G_CALLBACK(hce_handle_stop), profile);
	g_signal_connect(profile->skeleton, "handle-implicit-select",
	                 G_CALLBACK(hce_handle_implicit_select), profile);
	g_signal_connect(profile->skeleton, "handle-select",
	                 G_CALLBACK(hce_handle_select), profile);
	g_signal_connect(profile->skeleton, "handle-deselect",
	                 G_CALLBACK(hce_handle_deselect), profile);
	g_signal_connect(profile->skeleton, "handle-process",
	                 G_CALLBACK(hce_handle_process), profile);
	g_signal_connect(profile->skeleton, "handle-response-status",
	                 G_CALLBACK(hce_handle_response_status), profile);

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(profile->skeleton),
	                                      connection, profile->object_path, &error)) {
		g_warning("Failed to export card emulation object %s: %s",
		         profile->object_path, error->message);
		g_error_free(error);
		g_object_unref(profile->skeleton);
		profile->skeleton = NULL;
	}

	g_object_unref(connection);
	return profile->skeleton != NULL;
}

static void hce_mode_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct nfcd_client *client = user_data;
	NfcdInterfaceDaemon *daemon = NFCD_INTERFACE_DAEMON(source);
	GError *error = NULL;
	guint id = 0;

	if (nfcd_interface_daemon_call_request_mode_finish(daemon, &id, res, &error)) {
		if (client)
			client->hce_mode_request_id = id;
	} else {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning("Failed to request card emulation mode: %s", error->message);
		g_error_free(error);
	}
}

struct hce_req {
	struct hce_profile *profile;
	nfcd_result_cb cb;
	void *user_data;
};

static void hce_register_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct hce_req *req = user_data;
	NfcdInterfaceDaemon *daemon = NFCD_INTERFACE_DAEMON(source);
	GError *error = NULL;

	if (nfcd_interface_daemon_call_register_local_host_app_finish(daemon, res, &error)) {
		if (req->profile)
			req->profile->registered = TRUE;
		if (req->cb)
			req->cb(TRUE, NULL, req->user_data);
	} else {
		if (req->cb)
			req->cb(FALSE, error->message, req->user_data);
		g_error_free(error);
	}
	g_free(req);
}

static void hce_do_register(struct nfcd_client *client, struct hce_profile *profile,
                            const GByteArray *aid, nfcd_result_cb cb, void *user_data)
{
	struct hce_req *req;
	GVariant *aid_variant;
	guint flags = profile->implicit ? 0x01 : 0x00;

	if (!client->daemon) {
		if (cb)
			cb(FALSE, "nfcd is not available", user_data);
		return;
	}

	req = g_new0(struct hce_req, 1);
	req->profile = profile;
	req->cb = cb;
	req->user_data = user_data;

	nfcd_interface_daemon_call_request_mode(client->daemon,
		NFCD_MODE_CARD_EMULATION, 0, client->cancellable,
		hce_mode_ready, client);

	aid_variant = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
		aid->data, aid->len, 1);
	nfcd_interface_daemon_call_register_local_host_app(client->daemon,
		profile->object_path, NFCD_HCE_APP_NAME, aid_variant, flags,
		client->cancellable, hce_register_ready, req);
}

static void hce_profile_free(gpointer data)
{
	struct hce_profile *profile = data;

	if (profile->skeleton) {
		g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(profile->skeleton));
		g_object_unref(profile->skeleton);
	}
	if (profile->payload)
		g_byte_array_unref(profile->payload);
	g_free(profile->object_path);
	g_free(profile->aid_hex);
	g_free(profile);
}

void nfcd_client_add_card_emulation_profile(struct nfcd_client *client,
                                            const GByteArray *aid, const GByteArray *payload,
                                            gboolean implicit,
                                            nfcd_result_cb cb, void *user_data)
{
	struct hce_profile *profile;
	gchar *aid_hex;

	if (!aid || !aid->len) {
		if (cb)
			cb(FALSE, "AID is required", user_data);
		return;
	}

	if (!client->hce_profiles)
		client->hce_profiles = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                             NULL, hce_profile_free);

	aid_hex = ndef_bytes_to_hex(aid->data, aid->len);
	profile = g_hash_table_lookup(client->hce_profiles, aid_hex);

	if (profile) {
		/* Already registered - update the payload in place, only
		 * re-registering with nfcd if the implicit flag changed. */
		gboolean flag_changed = (profile->implicit != implicit);

		g_byte_array_set_size(profile->payload, 0);
		if (payload && payload->len)
			g_byte_array_append(profile->payload, payload->data, payload->len);
		profile->implicit = implicit;
		g_free(aid_hex);

		if (flag_changed && client->daemon) {
			nfcd_interface_daemon_call_unregister_local_host_app(client->daemon,
				profile->object_path, client->cancellable, NULL, NULL);
			profile->registered = FALSE;
			hce_do_register(client, profile, aid, cb, user_data);
		} else if (cb) {
			cb(TRUE, NULL, user_data);
		}
		return;
	}

	profile = g_new0(struct hce_profile, 1);
	profile->client = client;
	profile->aid_hex = aid_hex;
	profile->object_path = g_strdup_printf("%s/%s", NFCD_HCE_OBJECT_PATH, aid_hex);
	profile->payload = g_byte_array_sized_new(payload ? payload->len : 0);
	if (payload && payload->len)
		g_byte_array_append(profile->payload, payload->data, payload->len);
	profile->implicit = implicit;

	if (!hce_export_skeleton(profile)) {
		if (cb)
			cb(FALSE, "Failed to export card emulation object", user_data);
		hce_profile_free(profile);
		return;
	}

	g_hash_table_insert(client->hce_profiles, profile->aid_hex, profile);
	hce_do_register(client, profile, aid, cb, user_data);
}

void nfcd_client_remove_card_emulation_profile(struct nfcd_client *client,
                                               const GByteArray *aid,
                                               nfcd_result_cb cb, void *user_data)
{
	struct hce_profile *profile;
	gchar *aid_hex;

	if (!aid || !aid->len) {
		if (cb)
			cb(FALSE, "AID is required", user_data);
		return;
	}

	aid_hex = ndef_bytes_to_hex(aid->data, aid->len);
	profile = client->hce_profiles ?
		g_hash_table_lookup(client->hce_profiles, aid_hex) : NULL;

	if (!profile) {
		g_free(aid_hex);
		if (cb)
			cb(TRUE, NULL, user_data);
		return;
	}

	if (profile->registered && client->daemon) {
		/* nfcd also drops this on its own if our bus connection
		 * goes away, same as every other resource it hands out. */
		nfcd_interface_daemon_call_unregister_local_host_app(client->daemon,
			profile->object_path, client->cancellable, NULL, NULL);
	}

	g_hash_table_remove(client->hce_profiles, aid_hex);
	g_free(aid_hex);

	if (g_hash_table_size(client->hce_profiles) == 0 &&
	    client->hce_mode_request_id && client->daemon) {
		nfcd_interface_daemon_call_release_mode(client->daemon,
			client->hce_mode_request_id, client->cancellable, NULL, NULL);
		client->hce_mode_request_id = 0;
	}

	if (cb)
		cb(TRUE, NULL, user_data);
}

void nfcd_client_clear_card_emulation(struct nfcd_client *client,
                                      nfcd_result_cb cb, void *user_data)
{
	GHashTableIter iter;
	gpointer value;

	if (client->hce_profiles) {
		g_hash_table_iter_init(&iter, client->hce_profiles);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			struct hce_profile *profile = value;

			if (profile->registered && client->daemon)
				nfcd_interface_daemon_call_unregister_local_host_app(client->daemon,
					profile->object_path, client->cancellable, NULL, NULL);
		}
		g_hash_table_remove_all(client->hce_profiles);
	}

	if (client->hce_mode_request_id && client->daemon) {
		nfcd_interface_daemon_call_release_mode(client->daemon,
			client->hce_mode_request_id, client->cancellable, NULL, NULL);
		client->hce_mode_request_id = 0;
	}

	if (cb)
		cb(TRUE, NULL, user_data);
}

gboolean nfcd_client_get_hce_event(struct nfcd_client *client,
                                   gchar **aid_hex_out, gboolean *ok_out)
{
	if (!client->hce_event_aid_hex)
		return FALSE;

	if (aid_hex_out)
		*aid_hex_out = g_strdup(client->hce_event_aid_hex);
	if (ok_out)
		*ok_out = client->hce_event_ok;
	return TRUE;
}

gboolean nfcd_client_is_available(struct nfcd_client *client)
{
	return client->available;
}

gboolean nfcd_client_is_enabled(struct nfcd_client *client)
{
	return client->settings_valid ? client->settings_enabled : client->adapter_enabled;
}

gboolean nfcd_client_is_powered(struct nfcd_client *client)
{
	return client->powered;
}

gboolean nfcd_client_is_present(struct nfcd_client *client)
{
	return client->present;
}

guint nfcd_client_get_mode(struct nfcd_client *client)
{
	return client->mode;
}

guint nfcd_client_get_supported_modes(struct nfcd_client *client)
{
	return client->supported_modes;
}

guint nfcd_client_get_techs(struct nfcd_client *client)
{
	return client->techs;
}

gint nfcd_client_get_daemon_version(struct nfcd_client *client)
{
	return client->daemon_version;
}

const char *nfcd_client_get_adapter_path(struct nfcd_client *client)
{
	return client->adapter_path;
}

jvalue_ref nfcd_client_get_tag_json(struct nfcd_client *client)
{
	if (!client->tag_json)
		return NULL;

	return jvalue_duplicate(client->tag_json);
}

static void set_enabled_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct simple_req *req = user_data;
	NfcdInterfaceSettings *settings = NFCD_INTERFACE_SETTINGS(source);
	GError *error = NULL;

	if (nfcd_interface_settings_call_set_enabled_finish(settings, res, &error)) {
		req->cb(TRUE, NULL, req->user_data);
	} else {
		req->cb(FALSE, error->message, req->user_data);
		g_error_free(error);
	}

	g_free(req);
}

void nfcd_client_set_enabled(struct nfcd_client *client, gboolean enabled,
                             nfcd_result_cb cb, void *user_data)
{
	struct simple_req *req;

	if (!client->settings) {
		cb(FALSE, "nfcd settings interface is not available", user_data);
		return;
	}

	req = g_new0(struct simple_req, 1);
	req->client = client;
	req->cb = cb;
	req->user_data = user_data;

	nfcd_interface_settings_call_set_enabled(client->settings, enabled,
	                                         client->cancellable,
	                                         set_enabled_ready, req);
}

/*
 * Writing a tag. nfcd is asked for exclusive access first so that it doesn't
 * deactivate the tag underneath us, and the lock is handed back afterwards.
 */

static void write_req_finish(struct write_req *req, gboolean success, const char *error_text)
{
	req->cb(success, error_text, req->user_data);

	if (req->type2)
		g_object_unref(req->type2);

	if (req->tag)
		g_object_unref(req->tag);

	g_byte_array_free(req->tlv, TRUE);
	g_free(req->error_text);
	g_free(req);
}

static void write_release_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct write_req *req = user_data;
	NfcdInterfaceTag *tag = NFCD_INTERFACE_TAG(source);
	GError *error = NULL;

	if (!nfcd_interface_tag_call_release_finish(tag, res, &error)) {
		/* The write already landed, so this is only worth logging */
		g_warning("Failed to release tag after writing: %s", error->message);
		g_error_free(error);
	}

	write_req_finish(req, req->written, req->error_text);
}

static void write_release(struct write_req *req)
{
	nfcd_interface_tag_call_release(req->tag, req->client->cancellable,
	                                write_release_ready, req);
}

static void write_data_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct write_req *req = user_data;
	NfcdInterfaceTagType2 *type2 = NFCD_INTERFACE_TAG_TYPE2(source);
	GError *error = NULL;
	guint written = 0;

	if (nfcd_interface_tag_type2_call_write_data_finish(type2, &written, res, &error)) {
		req->written = (written == req->tlv->len);

		if (!req->written) {
			g_warning("Short write to tag: %u of %u bytes", written, req->tlv->len);
			req->error_text = g_strdup_printf("Only %u of %u bytes reached the tag",
			                                  written, req->tlv->len);
		}
	} else {
		g_warning("Failed to write tag: %s", error->message);
		req->error_text = g_strdup_printf("Failed to write the tag: %s", error->message);
		g_error_free(error);
		req->written = FALSE;
	}

	write_release(req);
}

static void write_type2_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct write_req *req = user_data;
	GError *error = NULL;
	GVariant *data;

	req->type2 = nfcd_interface_tag_type2_proxy_new_for_bus_finish(res, &error);

	if (!req->type2) {
		req->error_text = g_strdup_printf("Failed to reach the tag: %s", error->message);
		g_error_free(error);
		req->written = FALSE;

		/* The tag was already acquired, so give the lock back */
		write_release(req);
		return;
	}

	data = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, req->tlv->data,
	                                 req->tlv->len, 1);

	nfcd_interface_tag_type2_call_write_data(req->type2, 0, data,
	                                         req->client->cancellable,
	                                         write_data_ready, req);
}

static void write_acquire_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct write_req *req = user_data;
	NfcdInterfaceTag *tag = NFCD_INTERFACE_TAG(source);
	GError *error = NULL;

	if (!nfcd_interface_tag_call_acquire_finish(tag, res, &error)) {
		gchar *text = g_strdup_printf("Failed to acquire the tag: %s", error->message);

		g_error_free(error);
		write_req_finish(req, FALSE, text);
		g_free(text);
		return;
	}

	nfcd_interface_tag_type2_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                           NFCD_DAEMON_SERVICE,
	                                           req->client->tag_path,
	                                           req->client->cancellable,
	                                           write_type2_proxy_ready, req);
}

static void write_tag_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct write_req *req = user_data;
	GError *error = NULL;

	req->tag = nfcd_interface_tag_proxy_new_for_bus_finish(res, &error);

	if (!req->tag) {
		gchar *text = g_strdup_printf("Failed to reach the tag: %s", error->message);

		g_error_free(error);
		write_req_finish(req, FALSE, text);
		g_free(text);
		return;
	}

	/* wait = FALSE: the tag is already in the field, don't block if it isn't */
	nfcd_interface_tag_call_acquire(req->tag, FALSE, req->client->cancellable,
	                                write_acquire_ready, req);
}

/* Common to nfcd_client_write_tag and nfcd_client_write_raw: acquire the tag
 * and write the already-TLV-wrapped bytes verbatim. Takes ownership of tlv
 * regardless of outcome. */
static void start_type2_write(struct nfcd_client *client, GByteArray *tlv,
                              nfcd_result_cb cb, void *user_data)
{
	struct write_req *req;

	req = g_new0(struct write_req, 1);
	req->client = client;
	req->tlv = tlv;
	req->cb = cb;
	req->user_data = user_data;

	nfcd_interface_tag_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                     NFCD_DAEMON_SERVICE, client->tag_path,
	                                     client->cancellable,
	                                     write_tag_proxy_ready, req);
}

void nfcd_client_write_tag(struct nfcd_client *client, GByteArray *message,
                           nfcd_result_cb cb, void *user_data)
{
	GByteArray *tlv;

	if (!client->tag_path) {
		cb(FALSE, "No tag in the field", user_data);
		return;
	}

	if (!client->tag_is_type2) {
		cb(FALSE, "Only Type 2 tags can be written", user_data);
		return;
	}

	tlv = ndef_wrap_type2_tlv(message);
	if (!tlv) {
		cb(FALSE, "Failed to encode the NDEF message", user_data);
		return;
	}

	start_type2_write(client, tlv, cb, user_data);
}

void nfcd_client_write_raw(struct nfcd_client *client, const GByteArray *raw_data,
                           nfcd_result_cb cb, void *user_data)
{
	GByteArray *copy;

	if (!client->tag_path) {
		cb(FALSE, "No tag in the field", user_data);
		return;
	}

	if (!client->tag_is_type2) {
		cb(FALSE, "Only Type 2 tags can be written", user_data);
		return;
	}

	if (!raw_data || raw_data->len == 0) {
		cb(FALSE, "Nothing to write", user_data);
		return;
	}

	/* start_type2_write takes ownership; the caller still owns raw_data */
	copy = g_byte_array_sized_new(raw_data->len);
	g_byte_array_append(copy, raw_data->data, raw_data->len);

	start_type2_write(client, copy, cb, user_data);
}

/*
 * Locking a tag permanently, by setting the NFC Forum Type 2 static lock
 * bits in block 2 (bytes 2-3). This is the layout shared by the NTAG21x /
 * MIFARE Ultralight family, which covers the overwhelming majority of
 * writable tags people actually own; the dynamic lock area some larger tags
 * (NTAG216 and up) additionally have past their first ~48 bytes isn't
 * touched, so a very large tag may still have some writable pages after
 * this. There is no way back from this once it reaches the tag.
 */

struct lock_req {
	struct nfcd_client *client;
	NfcdInterfaceTag *tag;
	NfcdInterfaceTagType2 *type2;
	nfcd_result_cb cb;
	void *user_data;
	gchar *error_text;
};

static void lock_req_finish(struct lock_req *req, gboolean success, const char *error_text)
{
	req->cb(success, error_text, req->user_data);

	if (req->type2)
		g_object_unref(req->type2);

	if (req->tag)
		g_object_unref(req->tag);

	g_free(req->error_text);
	g_free(req);
}

static void lock_release_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct lock_req *req = user_data;
	NfcdInterfaceTag *tag = NFCD_INTERFACE_TAG(source);
	GError *error = NULL;

	if (!nfcd_interface_tag_call_release_finish(tag, res, &error)) {
		g_warning("Failed to release tag after locking: %s", error->message);
		g_error_free(error);
	}

	lock_req_finish(req, !req->error_text, req->error_text);
}

static void lock_release(struct lock_req *req)
{
	nfcd_interface_tag_call_release(req->tag, req->client->cancellable,
	                                lock_release_ready, req);
}

static void lock_write_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct lock_req *req = user_data;
	NfcdInterfaceTagType2 *type2 = NFCD_INTERFACE_TAG_TYPE2(source);
	GError *error = NULL;
	guint written = 0;

	if (!nfcd_interface_tag_type2_call_write_finish(type2, &written, res, &error)) {
		req->error_text = g_strdup_printf("Failed to write the lock bytes: %s",
		                                  error->message);
		g_error_free(error);
	} else if (written != 4) {
		req->error_text = g_strdup_printf("Short write of the lock block: %u of 4 bytes",
		                                  written);
	}

	lock_release(req);
}

static void lock_read_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct lock_req *req = user_data;
	NfcdInterfaceTagType2 *type2 = NFCD_INTERFACE_TAG_TYPE2(source);
	GError *error = NULL;
	GVariant *data = NULL;

	if (!nfcd_interface_tag_type2_call_read_finish(type2, &data, res, &error)) {
		req->error_text = g_strdup_printf("Failed to read the lock block: %s",
		                                  error->message);
		g_error_free(error);
		lock_release(req);
		return;
	}

	{
		gsize len = 0;
		const guint8 *block = g_variant_get_fixed_array(data, &len, 1);
		guint8 new_block[4];
		GVariant *new_data;

		if (len != 4) {
			req->error_text = g_strdup_printf("Unexpected lock block size: %zu bytes", len);
			g_variant_unref(data);
			lock_release(req);
			return;
		}

		/* Bytes 0-1 (BCC1, Internal) are preserved; 2-3 are the lock bytes.
		 * All-ones locks every static-locking-covered page, including these
		 * lock bytes themselves. */
		new_block[0] = block[0];
		new_block[1] = block[1];
		new_block[2] = 0xff;
		new_block[3] = 0xff;

		g_variant_unref(data);

		new_data = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, new_block, 4, 1);
		nfcd_interface_tag_type2_call_write(req->type2, 0, 2, new_data,
		                                    req->client->cancellable,
		                                    lock_write_ready, req);
	}
}

static void lock_type2_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct lock_req *req = user_data;
	GError *error = NULL;

	req->type2 = nfcd_interface_tag_type2_proxy_new_for_bus_finish(res, &error);

	if (!req->type2) {
		req->error_text = g_strdup_printf("Failed to reach the tag: %s", error->message);
		g_error_free(error);
		lock_release(req);
		return;
	}

	nfcd_interface_tag_type2_call_read(req->type2, 0, 2, req->client->cancellable,
	                                   lock_read_ready, req);
}

static void lock_acquire_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct lock_req *req = user_data;
	NfcdInterfaceTag *tag = NFCD_INTERFACE_TAG(source);
	GError *error = NULL;

	if (!nfcd_interface_tag_call_acquire_finish(tag, res, &error)) {
		gchar *text = g_strdup_printf("Failed to acquire the tag: %s", error->message);

		g_error_free(error);
		lock_req_finish(req, FALSE, text);
		g_free(text);
		return;
	}

	nfcd_interface_tag_type2_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                           NFCD_DAEMON_SERVICE,
	                                           req->client->tag_path,
	                                           req->client->cancellable,
	                                           lock_type2_proxy_ready, req);
}

static void lock_tag_proxy_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	struct lock_req *req = user_data;
	GError *error = NULL;

	req->tag = nfcd_interface_tag_proxy_new_for_bus_finish(res, &error);

	if (!req->tag) {
		gchar *text = g_strdup_printf("Failed to reach the tag: %s", error->message);

		g_error_free(error);
		lock_req_finish(req, FALSE, text);
		g_free(text);
		return;
	}

	nfcd_interface_tag_call_acquire(req->tag, FALSE, req->client->cancellable,
	                                lock_acquire_ready, req);
}

void nfcd_client_lock_tag(struct nfcd_client *client, nfcd_result_cb cb, void *user_data)
{
	struct lock_req *req;

	if (!client->tag_path) {
		cb(FALSE, "No tag in the field", user_data);
		return;
	}

	if (!client->tag_is_type2) {
		cb(FALSE, "Only Type 2 tags can be locked", user_data);
		return;
	}

	req = g_new0(struct lock_req, 1);
	req->client = client;
	req->cb = cb;
	req->user_data = user_data;

	nfcd_interface_tag_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
	                                     NFCD_DAEMON_SERVICE, client->tag_path,
	                                     client->cancellable,
	                                     lock_tag_proxy_ready, req);
}

// vim:ts=4:sw=4:noexpandtab
