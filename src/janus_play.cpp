/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include <glib.h>

extern "C" {
#include "plugin.h"
}

#include <dirent.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <jansson.h>

extern "C" {
#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../sdp-utils.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"
}

#include "glib_ptr.h"
#include "janus_play_recording.h"
#include "janus_play_frame_packet.h"
#include "janus_play_session.h"
#include "recording_reader.h"
using namespace play;


/* Plugin information */
#define JANUS_PLAY_VERSION			4
#define JANUS_PLAY_VERSION_STRING		"0.0.4"
#define JANUS_PLAY_DESCRIPTION		""
#define JANUS_PLAY_NAME				"JANUS Play plugin"
#define JANUS_PLAY_AUTHOR			"Meetecho s.r.l. && Sergey Radionov <rsatom@gmail.com>"
#define JANUS_PLAY_PACKAGE			"janus.plugin.play"

/* Plugin methods */
extern "C" janus_plugin *create(void);
static int janus_play_init(janus_callbacks *callback, const char *onfig_path);
static void janus_play_destroy(void);
static int janus_play_get_api_compatibility(void);
static int janus_play_get_version(void);
static const char *janus_play_get_version_string(void);
static const char *janus_play_get_description(void);
static const char *janus_play_get_name(void);
static const char *janus_play_get_author(void);
static const char *janus_play_get_package(void);
static void janus_play_create_session(janus_plugin_session *handle, int *error);
static struct janus_plugin_result *janus_play_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
static json_t *janus_play_handle_admin_message(json_t *message);
static void janus_play_setup_media(janus_plugin_session *handle);
static void janus_play_hangup_media(janus_plugin_session *handle);
static void janus_play_destroy_session(janus_plugin_session *handle, int *error);
static json_t *janus_play_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_play_plugin =
	janus_plugin {
		.init = janus_play_init,
		.destroy = janus_play_destroy,

		.get_api_compatibility = janus_play_get_api_compatibility,
		.get_version = janus_play_get_version,
		.get_version_string = janus_play_get_version_string,
		.get_description = janus_play_get_description,
		.get_name = janus_play_get_name,
		.get_author = janus_play_get_author,
		.get_package = janus_play_get_package,

		.create_session = janus_play_create_session,
		.handle_message = janus_play_handle_message,
		.handle_admin_message = janus_play_handle_admin_message,
		.setup_media = janus_play_setup_media,
		.hangup_media = janus_play_hangup_media,
		.destroy_session = janus_play_destroy_session,
		.query_session = janus_play_query_session,
	};

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_PLAY_NAME);
	return &janus_play_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter play_parameters[] = {
	{"id", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"restart", JANUS_JSON_BOOL, 0}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_play_handler(void *data);
static void janus_play_hangup_media_internal(janus_plugin_session *handle);

typedef struct janus_play_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_play_message;
static GAsyncQueue *messages = NULL;
static janus_play_message exit_message;

typedef struct janus_play_rtp_header_extension {
	uint16_t type;
	uint16_t length;
} janus_play_rtp_header_extension;

static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;


static char *recordings_path = NULL;
static void *janus_play_playout_thread(void *data);

static gchar_ptr build_recording_file_path(const char* recordings_dir, const char* id) {
	if(!recordings_dir || !id)
		return nullptr;

	if(!g_path_is_absolute(recordings_dir)) {
		JANUS_LOG(LOG_ERR, "Recordings path is not absolute: %s.\n", recordings_dir);
		return nullptr;
	}

	gchar_ptr mjr_file(g_strconcat(id, ".mjr", nullptr));
	gchar_ptr full_path(g_build_filename(recordings_dir, mjr_file.get(), nullptr));
	gchar_ptr safe_path(g_canonicalize_filename(full_path.get(), nullptr));

	if(!g_str_has_prefix(safe_path.get(), recordings_dir)) {
		JANUS_LOG(LOG_ERR, "Recording path escape detected: %s.\n", id);
		return nullptr;
	}

	return safe_path;
}

static void janus_play_message_free(janus_play_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_play_session *session = (janus_play_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}


/* Error codes */
#define JANUS_PLAY_ERROR_NO_MESSAGE			411
#define JANUS_PLAY_ERROR_INVALID_JSON			412
#define JANUS_PLAY_ERROR_INVALID_REQUEST		413
#define JANUS_PLAY_ERROR_INVALID_ELEMENT		414
#define JANUS_PLAY_ERROR_MISSING_ELEMENT		415
#define JANUS_PLAY_ERROR_NOT_FOUND			416
#define JANUS_PLAY_ERROR_INVALID_RECORDING	417
#define JANUS_PLAY_ERROR_INVALID_STATE		418
#define JANUS_PLAY_ERROR_INVALID_SDP			419
#define JANUS_PLAY_ERROR_RECORDING_EXISTS		420
#define JANUS_PLAY_ERROR_UNKNOWN_ERROR		499

#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

/* Plugin implementation */
int janus_play_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_PLAY_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_PLAY_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_PLAY_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL)
		janus_config_print(config);
	/* Parse configuration */
	if(config != NULL) {
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *path = janus_config_get(config, config_general, janus_config_type_item, "path");
		if(path && path->value)
			recordings_path = g_strdup(path->value);
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_PLAY_NAME);
		}
		/* Done */
		janus_config_destroy(config);
		config = NULL;
	}
	if(recordings_path == NULL) {
		JANUS_LOG(LOG_FATAL, "No recordings path specified, giving up...\n");
		return -1;
	}
	/* Create the folder, if needed */
	struct stat st = {0};
	if(stat(recordings_path, &st) == -1) {
		int res = janus_mkdir(recordings_path, 0755);
		JANUS_LOG(LOG_VERB, "Creating folder: %d\n", res);
		if(res != 0) {
			JANUS_LOG(LOG_ERR, "%s", g_strerror(errno));
			return -1;	/* No point going on... */
		}
	}

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_play_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_play_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("play handler", janus_play_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Record&Play handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_PLAY_NAME);
	return 0;
}

void janus_play_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_PLAY_NAME);
}

int janus_play_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_play_get_version(void) {
	return JANUS_PLAY_VERSION;
}

const char *janus_play_get_version_string(void) {
	return JANUS_PLAY_VERSION_STRING;
}

const char *janus_play_get_description(void) {
	return JANUS_PLAY_DESCRIPTION;
}

const char *janus_play_get_name(void) {
	return JANUS_PLAY_NAME;
}

const char *janus_play_get_author(void) {
	return JANUS_PLAY_AUTHOR;
}

const char *janus_play_get_package(void) {
	return JANUS_PLAY_PACKAGE;
}

static janus_play_session *janus_play_lookup_session(janus_plugin_session *handle) {
	janus_play_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_play_session *)handle->plugin_handle;
	}
	return session;
}

void janus_play_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_play_session *session = (janus_play_session *)g_malloc0(sizeof(janus_play_session));
	session->handle = handle;
	session->active = FALSE;
	session->firefox = FALSE;
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_rtp_switching_context_reset(&session->context);
	janus_refcount_init(&session->ref, janus_play_session_free);
	handle->plugin_handle = session;

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_play_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_play_session *session = janus_play_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No Record&Play session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing Record&Play session...\n");
	janus_play_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_play_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_play_session *session = janus_play_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "type", json_string(session->recording ? "player" : "none"));
	if(session->recording) {
		janus_refcount_increase(&session->recording->ref);
		json_object_set_new(info, "recording_id", json_string(session->recording->id));
		if(session->recording->e2ee)
			json_object_set_new(info, "e2ee", json_true());
		janus_refcount_decrease(&session->recording->ref);
	}
	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_play_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	janus_play_session *session = janus_play_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_PLAY_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");
		goto plugin_response;
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been destroyed...\n");
		error_code = JANUS_PLAY_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been destroyed...");
		goto plugin_response;
	}

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_PLAY_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_PLAY_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_PLAY_ERROR_MISSING_ELEMENT, JANUS_PLAY_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request; request = json_object_get(root, "request");
	/* Some requests ('create' and 'destroy') can be handled synchronously */
	const char *request_text; request_text = json_string_value(request);
	if(!strcasecmp(request_text, "play") || !strcasecmp(request_text, "start") || !strcasecmp(request_text, "stop")) {
		/* These messages are handled asynchronously */
		janus_play_message *msg = (janus_play_message *)g_malloc(sizeof(janus_play_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_PLAY_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code == 0 && !response) {
				error_code = JANUS_PLAY_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_t *event = json_object();
				json_object_set_new(event, "play", json_string("event"));
				json_object_set_new(event, "error_code", json_integer(error_code));
				json_object_set_new(event, "error", json_string(error_cause));
				response = event;
			}
			if(root != NULL)
				json_decref(root);
			if(jsep != NULL)
				json_decref(jsep);
			g_free(transaction);

			if(session != NULL)
				janus_refcount_decrease(&session->ref);
			return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		}

}

json_t *janus_play_handle_admin_message(json_t *message) {
	/* Some requests (e.g., 'update') can be handled via Admin API */
	int error_code = 0;
	char error_cause[512];
	json_t *response = NULL;

	JANUS_VALIDATE_JSON_OBJECT(message, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_PLAY_ERROR_MISSING_ELEMENT, JANUS_PLAY_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto admin_response;
	json_t *request; request = json_object_get(message, "request");
	const char *request_text; request_text = json_string_value(request);

	JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
	error_code = JANUS_PLAY_ERROR_INVALID_REQUEST;
	g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);

admin_response:
		{
			if(!response) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "play", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}

}

void janus_play_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_PLAY_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_play_session *session = janus_play_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	g_atomic_int_set(&session->hangingup, 0);
	/* Take note of the fact that the session is now active */
	session->active = TRUE;
	GError *error = NULL;
	janus_refcount_increase(&session->ref);
	g_thread_try_new("play playout thread", &janus_play_playout_thread, session, &error);
	if(error != NULL) {
		janus_refcount_decrease(&session->ref);
		/* FIXME Should we notify this back to the user somehow? */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Record&Play playout thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		gateway->close_pc(session->handle);
	}
	janus_refcount_decrease(&session->ref);
}

void janus_play_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_PLAY_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	janus_play_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_play_hangup_media_internal(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_play_session *session = janus_play_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	session->active = FALSE;
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	janus_rtp_switching_context_reset(&session->context);

	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "play", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	int ret = gateway->push_event(handle, &janus_play_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);

	session->active = FALSE;
	if(session->recording) {
		janus_refcount_decrease(&session->recording->ref);
		session->recording = NULL;
	}
	session->opusred = FALSE;
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_play_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Record&Play handler thread\n");
	janus_play_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = (janus_play_message *)g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_play_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_play_session *session = janus_play_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_play_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_play_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = NULL;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_PLAY_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_PLAY_ERROR_MISSING_ELEMENT, JANUS_PLAY_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		const char *msg_sdp_type; msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp; msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *request; request = json_object_get(root, "request");
		const char *request_text; request_text = json_string_value(request);
		json_t *event; event = NULL;
		json_t *result; result = NULL;
		char *sdp; sdp = NULL;
		gboolean sdp_update; sdp_update = FALSE;
		if(json_object_get(msg->jsep, "update") != NULL)
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
		gboolean e2ee; e2ee = json_is_true(json_object_get(msg->jsep, "e2ee"));
		const char *filename_text; filename_text = NULL;
		if(!strcasecmp(request_text, "play")) {
			if(msg_sdp) {
				JANUS_LOG(LOG_ERR, "A play request can't contain an SDP\n");
				error_code = JANUS_PLAY_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "A play request can't contain an SDP");
				goto error;
			}
			JANUS_LOG(LOG_VERB, "Replaying a recording\n");
			JANUS_VALIDATE_JSON_OBJECT(root, play_parameters,
				error_code, error_cause, TRUE,
				JANUS_PLAY_ERROR_MISSING_ELEMENT, JANUS_PLAY_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *restart = json_object_get(root, "restart");
			gboolean do_restart = restart ? json_is_true(restart) : FALSE;
			/* Check if this is a new playout, or if an update is taking place (i.e., ICE restart) */
			gchar_ptr id_value;
			janus_play_recording *rec = NULL;
			const char *warning = NULL;
			gchar_ptr recording_file;
			if(sdp_update || do_restart) {
				/* Renegotiation: make sure the user provided an offer, and send answer */
				JANUS_LOG(LOG_VERB, "Request to perform an ICE restart on existing playout\n");
				if(session->recording == NULL || session->recording->offer == NULL) {
					JANUS_LOG(LOG_ERR, "Not a playout session, can't restart\n");
					error_code = JANUS_PLAY_ERROR_INVALID_STATE;
					g_snprintf(error_cause, 512, "Not a playout session, can't restart");
					goto error;
				}
				rec = session->recording;
				id_value.reset(g_strdup(rec->id));
				session->sdp_version++;		/* This needs to be increased when it changes */
				sdp_update = TRUE;
				e2ee = rec->e2ee;
				/* Let's overwrite a couple o= fields, in case this is a renegotiation */
				char error_str[512];
				janus_sdp *offer = janus_sdp_parse(rec->offer, error_str, sizeof(error_str));
				if(offer == NULL) {
					JANUS_LOG(LOG_ERR, "Invalid offer, can't restart\n");
					error_code = JANUS_PLAY_ERROR_INVALID_STATE;
					g_snprintf(error_cause, 512, "Invalid, can't restart");
					goto error;
				}
				offer->o_sessid = session->sdp_sessid;
				offer->o_version = session->sdp_version;
				sdp = janus_sdp_write(offer);
				janus_sdp_destroy(offer);
				goto playdone;
			}
			/* If we got here, it's a new playout */
			json_t *id; id = json_object_get(root, "id");
			id_value.reset(g_strdup(json_string_value(id)));

			recording_file = build_recording_file_path(recordings_path, id_value.get());

			if(recording_file) {
				rec = create_recording(0, recording_file.get());
			}

			if(rec == NULL || rec->offer == NULL || g_atomic_int_get(&rec->destroyed)) {
				if(rec != NULL)
					janus_refcount_decrease(&rec->ref);
				JANUS_LOG(LOG_ERR, "No such recording\n");
				error_code = JANUS_PLAY_ERROR_NOT_FOUND;
				g_snprintf(error_cause, 512, "No such recording");
				goto error;
			}
			if(rec->opusred_pt > 0)
				session->opusred = TRUE;	/* Assume the user does support RED, if it's in the recording */
			session->recording = rec;
			e2ee = rec->e2ee;
			/* Send this viewer the prepared offer  */
			sdp = g_strdup(rec->offer);
playdone:
			JANUS_LOG(LOG_VERB, "Going to offer this SDP:\n%s\n", sdp);
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string(sdp_update ? "restarting" : "preparing"));
			json_object_set_new(result, "id", json_string(id_value.get()));
			if(warning)
				json_object_set_new(result, "warning", json_string(warning));
			/* Also notify event handlers */
			if(!sdp_update && notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("playout"));
				json_object_set_new(info, "id", json_string(id_value.get()));
				gateway->notify_event(&janus_play_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "start")) {
			/* Just a final message we make use of, e.g., to receive an ANSWER to our OFFER for a playout */
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP answer\n");
				error_code = JANUS_PLAY_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing SDP answer");
				goto error;
			}
			if(session->opusred && strstr(msg_sdp, "red/48000/2") == NULL)
				session->opusred = FALSE;
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string("playing"));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("playing"));
				json_object_set_new(info, "id", json_string(session->recording->id));
				gateway->notify_event(&janus_play_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "stop")) {
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string("stopped"));
			if(session->recording) {
				json_object_set_new(result, "id", json_string(session->recording->id));
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("stopped"));
					if(session->recording)
						json_object_set_new(info, "id", json_string(session->recording->id));
					gateway->notify_event(&janus_play_plugin, session->handle, info);
				}
			}
			/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
			gateway->close_pc(session->handle);
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
			error_code = JANUS_PLAY_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		event = json_object();
		json_object_set_new(event, "play", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);
		if(!sdp) {
			int ret = gateway->push_event(msg->handle, &janus_play_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			const char *type = "offer";
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", sdp);
			if(sdp_update)
				json_object_set_new(jsep, "restart", json_true());
			if(e2ee)
				json_object_set_new(jsep, "e2ee", json_true());
			/* How long will the gateway take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_play_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %" SCNu64 " us)\n",
				res, janus_get_monotonic_time()-start);
			g_free(sdp);
			json_decref(event);
			json_decref(jsep);
		}
		janus_play_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "play", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_play_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_play_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "LeavingRecord&Play handler thread\n");
	return NULL;
}

static void *janus_play_playout_thread(void *sessiondata) {
	janus_play_session *session = (janus_play_session *)sessiondata;
	if(!session) {
		JANUS_LOG(LOG_ERR, "Invalid session, can't start playout thread...\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	if(!session->recording) {
		janus_refcount_decrease(&session->ref);
		JANUS_LOG(LOG_ERR, "No recording object, can't start playout thread...\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	janus_refcount_increase(&session->recording->ref);
	janus_play_recording *rec = session->recording;

	JANUS_LOG(LOG_VERB, "Joining playout thread\n");

	/* Open the files */
	if(rec->arc_file == NULL) {
		janus_refcount_decrease(&rec->ref);
		janus_refcount_decrease(&session->ref);
		JANUS_LOG(LOG_ERR, "The recording session contains some audio packets but seems to lack a recording file name\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}

	recording_reader reader;
	if(!reader.open(rec->arc_file)) {
		janus_refcount_decrease(&rec->ref);
		janus_refcount_decrease(&session->ref);
		JANUS_LOG(LOG_ERR, "Could not open audio file %s, can't start playout thread...\n", rec->arc_file);
		g_thread_unref(g_thread_self());
		return NULL;
	}

	/* Timer */
	struct timeval now, abefore;
	time_t d_s, d_us;
	gettimeofday(&now, NULL);
	gettimeofday(&abefore, NULL);

	int64_t ts_diff = 0, passed = 0;

	const int audio_pt = session->recording->audio_pt;

	int akhz = 48;
	if(audio_pt == 0 || audio_pt == 8 || audio_pt == 9)
		akhz = 8;

	bool needs_sleep = false;
	unsigned eof_count = 0;
	const unsigned eof_sleep_time = 20; // milliseconds
	const unsigned max_eof_count = 1000 / eof_sleep_time; // 1 second
	while(!g_atomic_int_get(&session->destroyed) && session->active && !g_atomic_int_get(&rec->destroyed)) {
		if(needs_sleep) {
			/* We skipped the last round, so sleep a bit (5ms) */
			g_usleep(5000);
		} else {
			recording_reader::read_result read_result = reader.read_next_packet();

			if(read_result == recording_reader::read_result::eof) {
				++eof_count;
				if(eof_count >= max_eof_count) {
					JANUS_LOG(LOG_ERR, "Recording \"%s\" didn't grow for too long time. Terminating playout...\n", rec->arc_file);
					break;
				} else {
					g_usleep(eof_sleep_time * 1000);
					continue;
				}
			} else if(read_result != recording_reader::read_result::success) {
				break;
			}
		}

		needs_sleep = false;
		eof_count = 0;

		recording_packet& packet = reader.last_packet();

		if(!reader.prev_packet_header()) {
			/* Update payload type */
			janus_rtp_header *rtp = &packet.header();
			if(rec->opusred_pt == 0 || rtp->type != rec->opusred_pt)
				rtp->type = audio_pt;

			/* If the recording contains RED but the user doesn't support it, only use the primary data */
			if(rec->opusred_pt > 0 && rtp->type == rec->opusred_pt && !session->opusred) {
				int plen = 0;
				char *payload = janus_rtp_payload(packet.packet.data(), packet.packet.size(), &plen);
				if(payload && plen > 0) {
					GList *blocks = janus_red_parse_blocks(payload, plen);
					if(blocks != NULL) {
						/* Copy the last block (primary data) to the RTP payload */
						GList *last = g_list_last(blocks);
						janus_red_block *rb = (janus_red_block *)(last ? last->data : NULL);
						if(rb && rb->data && rb->length > 0) {
							rtp->type = audio_pt;
							memmove(payload, rb->data, rb->length);
							packet.packet.resize(packet.packet.size() - (plen - rb->length));
						}
						g_list_free_full(blocks, (GDestroyNotify)g_free);
					}
				}
			}
			janus_plugin_rtp prtp =
				{
					.mindex = -1,
					.video = FALSE,
					.buffer = packet.packet.data(),
					.length = (uint16_t)packet.packet.size()
				};
			janus_plugin_rtp_extensions_reset(&prtp.extensions);
			gateway->relay_rtp(session->handle, &prtp);
			gettimeofday(&now, NULL);
			abefore.tv_sec = now.tv_sec;
			abefore.tv_usec = now.tv_usec;
		} else {
			const play::rtp_header& prev_packet_header = reader.prev_packet_header().value();

			/* What's the timestamp skip from the previous packet? */
			ts_diff = packet.header().rtp_timestamp() - prev_packet_header.rtp_timestamp();
			ts_diff = (ts_diff*1000)/akhz;
			/* Check if it's time to send */
			gettimeofday(&now, NULL);
			d_s = now.tv_sec - abefore.tv_sec;
			d_us = now.tv_usec - abefore.tv_usec;
			if(d_us < 0) {
				d_us += 1000000;
				--d_s;
			}
			passed = d_s*1000000 + d_us;
			if(passed >= (ts_diff - 5000)) {
				/* Update the reference time */
				abefore.tv_usec += ts_diff % 1000000;
				if(abefore.tv_usec > 1000000) {
					abefore.tv_sec++;
					abefore.tv_usec -= 1000000;
				}
				if(ts_diff / 1000000 > 0) {
					abefore.tv_sec += ts_diff / 1000000;
					abefore.tv_usec -= ts_diff / 1000000;
				}

				/* Update payload type */
				janus_rtp_header *rtp = &packet.header();
				if(rec->opusred_pt == 0 || rtp->type != rec->opusred_pt)
					rtp->type = audio_pt;
				/* If the recording contains RED but the user doesn't support it, only use the primary data */
				if(rec->opusred_pt > 0 && rtp->type == rec->opusred_pt && !session->opusred) {
					int plen = 0;
					char *payload = janus_rtp_payload(packet.packet.data(), packet.packet.size(), &plen);
					if(payload && plen > 0) {
						GList *blocks = janus_red_parse_blocks(payload, plen);
						if(blocks != NULL) {
							/* Copy the last block (primary data) to the RTP payload */
							GList *last = g_list_last(blocks);
							janus_red_block *rb = (janus_red_block *)(last ? last->data : NULL);
							if(rb && rb->data && rb->length > 0) {
								rtp->type = audio_pt;
								memmove(payload, rb->data, rb->length);
								packet.packet.resize(packet.packet.size() - (plen - rb->length));
							}
							g_list_free_full(blocks, (GDestroyNotify)g_free);
						}
					}
				}
				janus_plugin_rtp prtp =
					{
						.mindex = -1,
						.video = FALSE,
						.buffer = packet.packet.data(),
						.length = (uint16_t)packet.packet.size()
					};
				janus_plugin_rtp_extensions_reset(&prtp.extensions);
				gateway->relay_rtp(session->handle, &prtp);
			} else {
				needs_sleep = true;
			}
		}
	}

	/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
	gateway->close_pc(session->handle);

	janus_refcount_decrease(&rec->ref);
	janus_refcount_decrease(&session->ref);

	JANUS_LOG(LOG_VERB, "Leaving playout thread\n");
	g_thread_unref(g_thread_self());
	return NULL;
}
