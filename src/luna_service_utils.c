/* @@@LICENSE
*
* Copyright (c) 2012 Simon Busch <morphis@gravedo.de>
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

#include "luna_service_utils.h"

void luna_service_message_reply_custom_error(LSHandle *handle, LSMessage *message,
                                             const char *error_text)
{
	LSError lserror;
	jvalue_ref reply_obj;
	jschema_ref schema;

	LSErrorInit(&lserror);

	/* Build the reply through pbnjson so that an error text containing
	 * quotes or backslashes can't break out of the JSON payload */
	reply_obj = jobject_create();
	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(false));
	jobject_put(reply_obj, J_CSTR_TO_JVAL("errorText"), jstring_create(error_text));

	schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if (schema) {
		if (!LSMessageReply(handle, message, jvalue_tostring(reply_obj, schema), &lserror)) {
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}

		jschema_release(&schema);
	}

	j_release(&reply_obj);
}

void luna_service_message_reply_error_bad_json(LSHandle *handle, LSMessage *message)
{
	luna_service_message_reply_custom_error(handle, message, "Malformed json.");
}

void luna_service_message_reply_error_invalid_params(LSHandle *handle, LSMessage *message)
{
	luna_service_message_reply_custom_error(handle, message, "Invalid parameters.");
}

void luna_service_message_reply_error_internal(LSHandle *handle, LSMessage *message)
{
	luna_service_message_reply_custom_error(handle, message, "Internal error.");
}

void luna_service_message_reply_success(LSHandle *handle, LSMessage *message)
{
	LSError lserror;

	LSErrorInit(&lserror);

	if (!LSMessageReply(handle, message, "{\"returnValue\":true}", &lserror)) {
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}
}

jvalue_ref luna_service_message_parse_and_validate(const char *payload)
{
	jschema_ref input_schema;
	jvalue_ref parsed_obj;
	JSchemaInfo schema_info;

	input_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if (!input_schema)
		return NULL;

	jschema_info_init(&schema_info, input_schema, NULL, NULL);

	parsed_obj = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT, &schema_info);

	jschema_release(&input_schema);

	if (jis_null(parsed_obj))
		return NULL;

	return parsed_obj;
}

bool luna_service_message_validate_and_send(LSHandle *handle, LSMessage *message,
                                            jvalue_ref reply_obj)
{
	jschema_ref response_schema;
	LSError lserror;
	bool success = true;

	LSErrorInit(&lserror);

	response_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if (!response_schema) {
		luna_service_message_reply_error_internal(handle, message);
		return false;
	}

	if (!LSMessageReply(handle, message, jvalue_tostring(reply_obj, response_schema),
	                    &lserror)) {
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
		success = false;
	}

	jschema_release(&response_schema);

	return success;
}

bool luna_service_check_for_subscription_and_process(LSHandle *handle, LSMessage *message)
{
	LSError lserror;
	bool subscribed = false;

	LSErrorInit(&lserror);

	if (LSMessageIsSubscription(message)) {
		if (!LSSubscriptionProcess(handle, message, &subscribed, &lserror)) {
			LSErrorPrint(&lserror, stderr);
			LSErrorFree(&lserror);
		}
	}

	return subscribed;
}

void luna_service_post_subscription(LSHandle *handle, const char *path,
                                    const char *method, jvalue_ref reply_obj)
{
	jschema_ref response_schema;
	LSError lserror;

	LSErrorInit(&lserror);

	response_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);
	if (!response_schema)
		return;

	if (!LSSubscriptionPost(handle, path, method,
	                        jvalue_tostring(reply_obj, response_schema), &lserror)) {
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	jschema_release(&response_schema);
}

// vim:ts=4:sw=4:noexpandtab
