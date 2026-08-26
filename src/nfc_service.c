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

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <luna-service2/lunaservice.h>

#include "nfc_service.h"
#include "nfcd_client.h"
#include "luna_service_utils.h"
#include "ndef.h"

#define NFC_SERVICE_NAME	"com.webos.service.nfc"

extern GMainLoop *event_loop;

struct nfc_service {
	LSHandle *handle;
	struct nfcd_client *client;
};

/* Keeps a message alive across an asynchronous nfcd call */
struct nfc_request {
	LSHandle *handle;
	LSMessage *message;
};

static struct nfc_request *nfc_request_new(LSHandle *handle, LSMessage *message)
{
	struct nfc_request *req = g_new0(struct nfc_request, 1);

	req->handle = handle;
	req->message = message;
	LSMessageRef(message);

	return req;
}

static void nfc_request_free(struct nfc_request *req)
{
	if (!req)
		return;

	LSMessageUnref(req->message);
	g_free(req);
}

/*
 * Reply builders. Both getStatus and getTagInfo are subscribable, so the same
 * body is used for the direct reply and for subscription updates.
 */

static jvalue_ref build_status(struct nfc_service *service)
{
	struct nfcd_client *client = service->client;
	jvalue_ref reply_obj = jobject_create();
	const char *adapter_path;

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("available"),
	            jboolean_create(nfcd_client_is_available(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("enabled"),
	            jboolean_create(nfcd_client_is_enabled(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("powered"),
	            jboolean_create(nfcd_client_is_powered(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("present"),
	            jboolean_create(nfcd_client_is_present(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("mode"),
	            jnumber_create_i32((int) nfcd_client_get_mode(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("supportedModes"),
	            jnumber_create_i32((int) nfcd_client_get_supported_modes(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("techs"),
	            jnumber_create_i32((int) nfcd_client_get_techs(client)));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("daemonVersion"),
	            jnumber_create_i32(nfcd_client_get_daemon_version(client)));

	adapter_path = nfcd_client_get_adapter_path(client);
	if (adapter_path)
		jobject_put(reply_obj, J_CSTR_TO_JVAL("adapterPath"), jstring_create(adapter_path));

	return reply_obj;
}

static jvalue_ref build_tag_info(struct nfc_service *service)
{
	jvalue_ref reply_obj = jobject_create();
	jvalue_ref tag_obj;

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("present"),
	            jboolean_create(nfcd_client_is_present(service->client)));

	tag_obj = nfcd_client_get_tag_json(service->client);
	if (tag_obj)
		jobject_put(reply_obj, J_CSTR_TO_JVAL("tag"), tag_obj);

	return reply_obj;
}

static jvalue_ref build_hce_event(struct nfc_service *service)
{
	jvalue_ref reply_obj = jobject_create();
	gchar *aid_hex = NULL;
	gboolean ok = FALSE;

	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	/* No fields beyond returnValue until a reader has actually confirmed
	 * receiving a card-emulation response - see nfcd_client_get_hce_event(). */
	if (nfcd_client_get_hce_event(service->client, &aid_hex, &ok)) {
		jobject_put(reply_obj, J_CSTR_TO_JVAL("aidHex"), jstring_create(aid_hex));
		jobject_put(reply_obj, J_CSTR_TO_JVAL("ok"), jboolean_create(ok));
		g_free(aid_hex);
	}

	return reply_obj;
}

static void state_changed_cb(struct nfcd_client *client, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref reply_obj;

	reply_obj = build_status(service);
	luna_service_post_subscription(service->handle, "/", "getStatus", reply_obj);
	j_release(&reply_obj);

	/*
	 * "present" is part of the tag reply too, so a target coming or going
	 * has to reach getTagInfo subscribers as well.
	 */
	reply_obj = build_tag_info(service);
	luna_service_post_subscription(service->handle, "/", "getTagInfo", reply_obj);
	j_release(&reply_obj);
}

static void tag_changed_cb(struct nfcd_client *client, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref reply_obj;

	reply_obj = build_tag_info(service);
	luna_service_post_subscription(service->handle, "/", "getTagInfo", reply_obj);
	j_release(&reply_obj);
}

static void hce_changed_cb(struct nfcd_client *client, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref reply_obj = build_hce_event(service);

	luna_service_post_subscription(service->handle, "/", "getCardEmulationEvent", reply_obj);
	j_release(&reply_obj);
}

/*
 * Methods
 */

static bool _service_get_status_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref reply_obj;
	bool subscribed;

	subscribed = luna_service_check_for_subscription_and_process(handle, message);

	reply_obj = build_status(service);
	jobject_put(reply_obj, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	luna_service_message_validate_and_send(handle, message, reply_obj);

	j_release(&reply_obj);

	return true;
}

static bool _service_get_tag_info_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref reply_obj;
	bool subscribed;

	subscribed = luna_service_check_for_subscription_and_process(handle, message);

	reply_obj = build_tag_info(service);
	jobject_put(reply_obj, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	luna_service_message_validate_and_send(handle, message, reply_obj);

	j_release(&reply_obj);

	return true;
}

static void set_enabled_result_cb(gboolean success, const char *error_text, void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to set NFC state");

	nfc_request_free(req);
}

static bool _service_set_enabled_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	jvalue_ref enabled_obj = NULL;
	bool enabled = false;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	/* jboolean_get follows the pbnjson convention of returning 0 on success */
	if (!jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("enabled"), &enabled_obj) ||
	    !jis_boolean(enabled_obj) ||
	    jboolean_get(enabled_obj, &enabled) != 0) {
		luna_service_message_reply_error_invalid_params(handle, message);
		j_release(&parsed_obj);
		return true;
	}

	j_release(&parsed_obj);

	nfcd_client_set_enabled(service->client, enabled ? TRUE : FALSE,
	                        set_enabled_result_cb, nfc_request_new(handle, message));

	return true;
}

static void write_tag_result_cb(gboolean success, const char *error_text, void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to write tag");

	nfc_request_free(req);
}

/* Pulls a string field out of the request, or NULL when it isn't a string */
static gchar *get_string_param(jvalue_ref parsed_obj, const char *name)
{
	jvalue_ref value_obj = NULL;
	raw_buffer buf;

	if (!jobject_get_exists(parsed_obj, j_cstr_to_buffer(name), &value_obj))
		return NULL;

	if (!jis_string(value_obj))
		return NULL;

	buf = jstring_get_fast(value_obj);

	return g_strndup(buf.m_str, buf.m_len);
}

static bool _service_write_tag_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	gchar *type = NULL, *uri = NULL, *text = NULL, *language = NULL;
	gchar *name = NULL, *phone = NULL, *email = NULL;
	gchar *ssid = NULL, *password = NULL, *auth = NULL, *encryption = NULL;
	gchar *mac_address = NULL, *device_name = NULL;
	GByteArray *ndef_message = NULL;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	type = get_string_param(parsed_obj, "type");
	uri = get_string_param(parsed_obj, "uri");
	text = get_string_param(parsed_obj, "text");
	language = get_string_param(parsed_obj, "language");
	name = get_string_param(parsed_obj, "name");
	phone = get_string_param(parsed_obj, "phone");
	email = get_string_param(parsed_obj, "email");
	ssid = get_string_param(parsed_obj, "ssid");
	password = get_string_param(parsed_obj, "password");
	auth = get_string_param(parsed_obj, "auth");
	encryption = get_string_param(parsed_obj, "encryption");
	mac_address = get_string_param(parsed_obj, "macAddress");
	device_name = get_string_param(parsed_obj, "deviceName");

	j_release(&parsed_obj);

	if (!g_strcmp0(type, "uri") && uri)
		ndef_message = ndef_build_uri_message(uri);
	else if (!g_strcmp0(type, "text") && text)
		ndef_message = ndef_build_text_message(text, language);
	else if (!g_strcmp0(type, "vcard") && name)
		ndef_message = ndef_build_vcard_message(name, phone, email);
	else if (!g_strcmp0(type, "wifi") && ssid)
		ndef_message = ndef_build_wifi_message(ssid, password, auth, encryption);
	else if (!g_strcmp0(type, "bluetooth") && mac_address)
		ndef_message = ndef_build_bluetooth_message(mac_address, device_name);

	if (!ndef_message) {
		luna_service_message_reply_custom_error(handle, message,
			"Expected type \"uri\" with a uri, type \"text\" with a text, "
			"type \"vcard\" with a name (phone/email optional), "
			"type \"wifi\" with a ssid (password/auth/encryption optional), "
			"or type \"bluetooth\" with a macAddress (deviceName optional)");
		goto cleanup;
	}

	nfcd_client_write_tag(service->client, ndef_message,
	                      write_tag_result_cb, nfc_request_new(handle, message));

	g_byte_array_free(ndef_message, TRUE);

cleanup:
	g_free(type);
	g_free(uri);
	g_free(text);
	g_free(language);
	g_free(name);
	g_free(phone);
	g_free(email);
	g_free(ssid);
	g_free(password);
	g_free(auth);
	g_free(encryption);
	g_free(mac_address);
	g_free(device_name);

	return true;
}

static void lock_tag_result_cb(gboolean success, const char *error_text, void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to lock tag");

	nfc_request_free(req);
}

static bool _service_lock_tag_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;

	nfcd_client_lock_tag(service->client, lock_tag_result_cb,
	                     nfc_request_new(handle, message));

	return true;
}

static void clone_tag_result_cb(gboolean success, const char *error_text, void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to clone tag");

	nfc_request_free(req);
}

static bool _service_clone_tag_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	gchar *raw_data_hex = NULL;
	GByteArray *raw_data;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	/* Expected to be the "rawDataHex" field from an earlier getTagInfo
	 * response for the tag being cloned - see cloneTag's doc comment */
	raw_data_hex = get_string_param(parsed_obj, "rawDataHex");

	j_release(&parsed_obj);

	raw_data = ndef_hex_to_bytes(raw_data_hex);
	g_free(raw_data_hex);

	if (!raw_data) {
		luna_service_message_reply_custom_error(handle, message,
			"Expected rawDataHex, the raw byte string read from the source tag");
		return true;
	}

	nfcd_client_write_raw(service->client, raw_data,
	                      clone_tag_result_cb, nfc_request_new(handle, message));

	g_byte_array_free(raw_data, TRUE);

	return true;
}

static void add_card_emulation_result_cb(gboolean success, const char *error_text,
                                         void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to add card emulation profile");

	nfc_request_free(req);
}

static bool _service_add_card_emulation_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	jvalue_ref implicit_obj = NULL;
	gchar *aid_hex = NULL;
	gchar *payload_hex = NULL;
	GByteArray *aid, *payload;
	bool implicit = false;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	/*
	 * aidHex: the ISO 7816-5 Application ID a reader selects to reach
	 * this profile - several profiles can be active at once, one per
	 * distinct AID. payloadHex: the fixed bytes returned for a
	 * read-style APDU once selected - a personal identifier, not card
	 * data. Both are plain hex strings, same encoding as getTagInfo's
	 * rawDataHex. implicit: also answer a reader that skips explicit
	 * AID-SELECT and lets this be the default profile.
	 */
	aid_hex = get_string_param(parsed_obj, "aidHex");
	payload_hex = get_string_param(parsed_obj, "payloadHex");

	if (jobject_get_exists(parsed_obj, J_CSTR_TO_BUF("implicit"), &implicit_obj) &&
	    jis_boolean(implicit_obj))
		jboolean_get(implicit_obj, &implicit);

	j_release(&parsed_obj);

	aid = ndef_hex_to_bytes(aid_hex);
	g_free(aid_hex);

	if (!aid) {
		luna_service_message_reply_custom_error(handle, message,
			"Expected aidHex, the Application ID to register");
		g_free(payload_hex);
		return true;
	}

	payload = ndef_hex_to_bytes(payload_hex);
	g_free(payload_hex);

	nfcd_client_add_card_emulation_profile(service->client, aid, payload,
	                                       implicit ? TRUE : FALSE,
	                                       add_card_emulation_result_cb,
	                                       nfc_request_new(handle, message));

	g_byte_array_free(aid, TRUE);
	if (payload)
		g_byte_array_free(payload, TRUE);

	return true;
}

static void remove_card_emulation_result_cb(gboolean success, const char *error_text,
                                            void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to remove card emulation profile");

	nfc_request_free(req);
}

static bool _service_remove_card_emulation_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	gchar *aid_hex = NULL;
	GByteArray *aid;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	aid_hex = get_string_param(parsed_obj, "aidHex");
	j_release(&parsed_obj);

	aid = ndef_hex_to_bytes(aid_hex);
	g_free(aid_hex);

	if (!aid) {
		luna_service_message_reply_custom_error(handle, message,
			"Expected aidHex, the Application ID to unregister");
		return true;
	}

	nfcd_client_remove_card_emulation_profile(service->client, aid,
	                                          remove_card_emulation_result_cb,
	                                          nfc_request_new(handle, message));

	g_byte_array_free(aid, TRUE);

	return true;
}

static void clear_card_emulation_result_cb(gboolean success, const char *error_text,
                                           void *user_data)
{
	struct nfc_request *req = user_data;

	if (success)
		luna_service_message_reply_success(req->handle, req->message);
	else
		luna_service_message_reply_custom_error(req->handle, req->message,
		                                        error_text ? error_text : "Failed to clear card emulation profile");

	nfc_request_free(req);
}

static bool _service_clear_card_emulation_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;

	nfcd_client_clear_card_emulation(service->client, clear_card_emulation_result_cb,
	                                 nfc_request_new(handle, message));

	return true;
}

static bool _service_get_card_emulation_event_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref reply_obj;
	bool subscribed;

	subscribed = luna_service_check_for_subscription_and_process(handle, message);

	reply_obj = build_hce_event(service);
	jobject_put(reply_obj, J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribed));

	luna_service_message_validate_and_send(handle, message, reply_obj);

	j_release(&reply_obj);

	return true;
}

static void read_passport_result_cb(gboolean success, const char *error_text,
                                    const char *mrz_text, void *user_data)
{
	struct nfc_request *req = user_data;

	if (success) {
		jvalue_ref reply_obj = jobject_create();

		jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));
		jobject_put(reply_obj, J_CSTR_TO_JVAL("mrz"), jstring_create(mrz_text));
		luna_service_message_validate_and_send(req->handle, req->message, reply_obj);
		j_release(&reply_obj);
	} else {
		luna_service_message_reply_custom_error(req->handle, req->message,
			error_text ? error_text : "Failed to read the document");
	}

	nfc_request_free(req);
}

static bool _service_read_passport_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	gchar *document_number = NULL, *date_of_birth = NULL, *date_of_expiry = NULL;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	/*
	 * The same three fields printed in the document's own MRZ - proof
	 * the caller already holds the physical document, which is what BAC
	 * itself relies on. Dates are YYMMDD; check digits are computed
	 * here, not expected from the caller.
	 */
	document_number = get_string_param(parsed_obj, "documentNumber");
	date_of_birth = get_string_param(parsed_obj, "dateOfBirth");
	date_of_expiry = get_string_param(parsed_obj, "dateOfExpiry");

	j_release(&parsed_obj);

	if (!document_number || !date_of_birth || !date_of_expiry) {
		luna_service_message_reply_custom_error(handle, message,
			"Expected documentNumber, dateOfBirth and dateOfExpiry (YYMMDD), "
			"as printed in the document's MRZ");
		g_free(document_number);
		g_free(date_of_birth);
		g_free(date_of_expiry);
		return true;
	}

	nfcd_client_read_passport(service->client, document_number, date_of_birth, date_of_expiry,
	                          read_passport_result_cb, nfc_request_new(handle, message));

	g_free(document_number);
	g_free(date_of_birth);
	g_free(date_of_expiry);

	return true;
}

/*
 * Same result shape as readPassport, but via PACE (the CAN printed on the
 * document) - what documents that reject readPassport with an
 * "instead of BAC" error need instead. A separate method rather than a
 * fallback inside readPassport: the two need different input (a CAN, not
 * three MRZ fields) and the caller (who's holding the document and can
 * see which one is printed on it) already knows which applies.
 */
static bool _service_read_passport_pace_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	struct nfc_service *service = user_data;
	jvalue_ref parsed_obj = NULL;
	gchar *can = NULL;

	parsed_obj = luna_service_message_parse_and_validate(LSMessageGetPayload(message));
	if (!parsed_obj) {
		luna_service_message_reply_error_bad_json(handle, message);
		return true;
	}

	can = get_string_param(parsed_obj, "can");
	j_release(&parsed_obj);

	if (!can) {
		luna_service_message_reply_custom_error(handle, message,
			"Expected can, the Card Access Number printed on the document");
		return true;
	}

	nfcd_client_read_passport_pace(service->client, can,
	                               read_passport_result_cb, nfc_request_new(handle, message));

	g_free(can);

	return true;
}

static LSMethod _nfc_service_methods[] = {
	{ "getStatus", _service_get_status_cb },
	{ "setEnabled", _service_set_enabled_cb },
	{ "getTagInfo", _service_get_tag_info_cb },
	{ "writeTag", _service_write_tag_cb },
	{ "lockTag", _service_lock_tag_cb },
	{ "cloneTag", _service_clone_tag_cb },
	{ "readPassport", _service_read_passport_cb },
	{ "readPassportPACE", _service_read_passport_pace_cb },
	{ "addCardEmulationProfile", _service_add_card_emulation_cb },
	{ "removeCardEmulationProfile", _service_remove_card_emulation_cb },
	{ "clearCardEmulation", _service_clear_card_emulation_cb },
	{ "getCardEmulationEvent", _service_get_card_emulation_event_cb },
	{ NULL, NULL },
};

struct nfc_service *nfc_service_create(void)
{
	struct nfc_service *service;
	LSError error;

	LSErrorInit(&error);

	service = g_new0(struct nfc_service, 1);

	if (!LSRegister(NFC_SERVICE_NAME, &service->handle, &error)) {
		g_critical("Failed to register %s: %s", NFC_SERVICE_NAME, error.message);
		LSErrorFree(&error);
		goto failed;
	}

	if (!LSGmainAttach(service->handle, event_loop, &error)) {
		g_critical("Failed to attach %s to the main loop: %s", NFC_SERVICE_NAME,
		           error.message);
		LSErrorFree(&error);
		goto failed;
	}

	if (!LSRegisterCategory(service->handle, "/", _nfc_service_methods, NULL, NULL,
	                        &error)) {
		g_critical("Failed to register the service category: %s", error.message);
		LSErrorFree(&error);
		goto failed;
	}

	if (!LSCategorySetData(service->handle, "/", service, &error)) {
		g_critical("Failed to set the service category data: %s", error.message);
		LSErrorFree(&error);
		goto failed;
	}

	service->client = nfcd_client_create(state_changed_cb, tag_changed_cb, hce_changed_cb, service);

	return service;

failed:
	if (service->handle) {
		LSError unregister_error;

		LSErrorInit(&unregister_error);

		if (!LSUnregister(service->handle, &unregister_error))
			LSErrorFree(&unregister_error);
	}

	g_free(service);

	return NULL;
}

void nfc_service_free(struct nfc_service *service)
{
	LSError error;

	if (!service)
		return;

	LSErrorInit(&error);

	if (service->client)
		nfcd_client_free(service->client);

	if (service->handle && !LSUnregister(service->handle, &error)) {
		LSErrorPrint(&error, stderr);
		LSErrorFree(&error);
	}

	g_free(service);
}

// vim:ts=4:sw=4:noexpandtab
