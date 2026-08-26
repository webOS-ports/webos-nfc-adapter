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

#ifndef NFCD_CLIENT_H_
#define NFCD_CLIENT_H_

#include <glib.h>
#include <pbnjson.h>

/**
 * Client for the nfcd D-Bus API. Two bus names on the system bus are involved:
 *
 *   org.sailfishos.nfc.daemon    the daemon, adapters, tags and NDEF records
 *   org.sailfishos.nfc.settings  the persistent enabled flag
 *
 * Both are watched, so nfcd restarting or not being installed at all is a
 * normal state rather than an error: the client simply reports unavailable
 * and re-attaches when nfcd comes back.
 *
 * Requires nfcd >= 1.2.0 for the GetAll4 calls.
 */

struct nfcd_client;

/* The daemon, adapter or settings state changed */
typedef void (*nfcd_state_cb)(struct nfcd_client *client, void *user_data);

/* The tag in the field changed: arrived and finished reading, or went away */
typedef void (*nfcd_tag_cb)(struct nfcd_client *client, void *user_data);

/* Completion of a request that can fail */
typedef void (*nfcd_result_cb)(gboolean success, const char *error_text, void *user_data);

struct nfcd_client *nfcd_client_create(nfcd_state_cb state_cb, nfcd_tag_cb tag_cb,
                                       void *user_data);
void nfcd_client_free(struct nfcd_client *client);

/* True once nfcd is running and has published an adapter */
gboolean nfcd_client_is_available(struct nfcd_client *client);
gboolean nfcd_client_is_enabled(struct nfcd_client *client);
gboolean nfcd_client_is_powered(struct nfcd_client *client);
/* True while a tag or peer is in the field */
gboolean nfcd_client_is_present(struct nfcd_client *client);

guint nfcd_client_get_mode(struct nfcd_client *client);
guint nfcd_client_get_supported_modes(struct nfcd_client *client);
guint nfcd_client_get_techs(struct nfcd_client *client);
gint nfcd_client_get_daemon_version(struct nfcd_client *client);
const char *nfcd_client_get_adapter_path(struct nfcd_client *client);

/**
 * The tag currently in the field, already decoded, or NULL when there is none
 * or it hasn't finished being read yet. The caller takes a reference.
 */
jvalue_ref nfcd_client_get_tag_json(struct nfcd_client *client);

void nfcd_client_set_enabled(struct nfcd_client *client, gboolean enabled,
                             nfcd_result_cb cb, void *user_data);

/**
 * Writes an NDEF message to the Type 2 tag currently in the field. Takes
 * ownership of nothing: the caller still owns message.
 */
void nfcd_client_write_tag(struct nfcd_client *client, GByteArray *message,
                           nfcd_result_cb cb, void *user_data);

/**
 * Writes an already-Type-2-TLV-wrapped byte blob to the tag currently in the
 * field verbatim, with no NDEF re-encoding. This is what cloneTag uses to
 * replay a source tag's "rawDataHex" byte for byte. Takes ownership of
 * nothing: the caller still owns raw_data.
 */
void nfcd_client_write_raw(struct nfcd_client *client, const GByteArray *raw_data,
                           nfcd_result_cb cb, void *user_data);

/**
 * Permanently write-protects the Type 2 tag currently in the field by
 * setting its static lock bits. Irreversible - see the comment above the
 * implementation for exactly what this does and doesn't cover.
 */
void nfcd_client_lock_tag(struct nfcd_client *client, nfcd_result_cb cb, void *user_data);

#endif

// vim:ts=4:sw=4:noexpandtab
