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

#define NFCD_DAEMON_SERVICE		"org.sailfishos.nfc.daemon"
#define NFCD_SETTINGS_SERVICE	"org.sailfishos.nfc.settings"
#define NFCD_ROOT_PATH			"/"

#define TAG_IFACE_TYPE2			"org.sailfishos.nfc.TagType2"

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

	/* The enabled flag is owned by the settings plugin, but the adapter
	 * reports it too. Prefer the settings value when we have it. */
	gboolean settings_valid;
	gboolean settings_enabled;
	gboolean adapter_enabled;

	gchar *tag_path;
	gboolean tag_is_type2;
	jvalue_ref tag_json;
	struct tag_read *reading;

	nfcd_state_cb state_cb;
	nfcd_tag_cb tag_cb;
	void *user_data;
};

/* One sequential walk over a tag and its NDEF records */
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
};

struct write_req {
	struct nfcd_client *client;
	GByteArray *tlv;
	NfcdInterfaceTag *tag;
	NfcdInterfaceTagType2 *type2;
	nfcd_result_cb cb;
	void *user_data;
	gboolean written;
};

struct simple_req {
	struct nfcd_client *client;
	nfcd_result_cb cb;
	void *user_data;
};

static void tag_read_start(struct nfcd_client *client, const char *path);
static void tag_read_next_record(struct tag_read *read);
static void tag_read_free(struct tag_read *read);

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

	g_strfreev(read->record_paths);
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

static void tag_read_next_record(struct tag_read *read)
{
	const char *path;

	if (!read->record_paths || !read->record_paths[read->record_index]) {
		tag_read_finish(read);
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

	for (n = 0; interfaces && interfaces[n]; n++) {
		if (!g_strcmp0(interfaces[n], TAG_IFACE_TYPE2))
			read->is_type2 = TRUE;
	}

	read->records_arr = jarray_create(NULL);
	read->record_paths = ndef_records;
	read->record_index = 0;

	g_strfreev(interfaces);
	g_variant_unref(poll_parameters);

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

static void set_current_tag(struct nfcd_client *client, const char *path)
{
	if (!g_strcmp0(client->tag_path, path))
		return;

	if (client->reading) {
		tag_read_abort(client->reading);
		client->reading = NULL;
	}

	g_free(client->tag_path);
	client->tag_path = g_strdup(path);
	client->tag_is_type2 = FALSE;

	if (client->tag_json)
		j_release(&client->tag_json);

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

	g_signal_connect(daemon, "adapters-changed",
	                 G_CALLBACK(daemon_adapters_changed), client);

	nfcd_interface_daemon_call_get_all4(daemon, client->cancellable,
	                                    daemon_get_all_ready, client);
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
                                       void *user_data)
{
	struct nfcd_client *client;

	client = g_new0(struct nfcd_client, 1);
	client->state_cb = state_cb;
	client->tag_cb = tag_cb;
	client->user_data = user_data;
	client->cancellable = g_cancellable_new();

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

	g_object_unref(client->cancellable);
	g_free(client->adapter_path);
	g_free(client->tag_path);
	g_free(client);
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

	write_req_finish(req, req->written, req->written ? NULL : "Failed to write tag");
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

		if (!req->written)
			g_warning("Short write to tag: %u of %u bytes", written, req->tlv->len);
	} else {
		g_warning("Failed to write tag: %s", error->message);
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
		gchar *text = g_strdup_printf("Failed to reach the tag: %s", error->message);

		g_error_free(error);
		req->written = FALSE;
		write_req_finish(req, FALSE, text);
		g_free(text);
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

void nfcd_client_write_tag(struct nfcd_client *client, GByteArray *message,
                           nfcd_result_cb cb, void *user_data)
{
	struct write_req *req;
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

// vim:ts=4:sw=4:noexpandtab
