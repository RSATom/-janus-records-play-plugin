/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "plugin.h"

#include <dirent.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../sdp-utils.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_PLAY_VERSION			4
#define JANUS_PLAY_VERSION_STRING		"0.0.4"
#define JANUS_PLAY_DESCRIPTION		""
#define JANUS_PLAY_NAME				"JANUS Play plugin"
#define JANUS_PLAY_AUTHOR			"Meetecho s.r.l. && Sergey Radionov <rsatom@gmail.com>"
#define JANUS_PLAY_PACKAGE			"janus.plugin.play"

/* Plugin methods */
janus_plugin *create(void);
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
	JANUS_PLUGIN_INIT (
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
	);

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
	{"id", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
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

typedef struct janus_play_frame_packet {
	uint16_t seq;	/* RTP Sequence number */
	uint64_t ts;	/* RTP Timestamp */
	int len;		/* Length of the data */
	long offset;	/* Offset of the data in the file */
	struct janus_play_frame_packet *next;
	struct janus_play_frame_packet *prev;
} janus_play_frame_packet;
janus_play_frame_packet *janus_play_get_frames(const char *dir, const char *filename);

typedef struct janus_play_recording {
	guint64 id;					/* Recording unique ID */
	char *name;					/* Name of the recording */
	char *date;					/* Time of the recording */
	char *arc_file;				/* Audio file name */
	janus_audiocodec acodec;	/* Codec used for audio, if available */
	char *afmtp;				/* Audio fmtp, if any */
	int audio_pt;				/* Payload type to use for audio when playing recordings */
	int opusred_pt;				/* In case RED is used for audio, payload type to use in playback */
	guint8 audiolevel_ext_id;	/* Audio level extmap ID */
	char *offer;				/* The SDP offer that will be sent to watchers */
	gboolean e2ee;				/* Whether media in the recording is encrypted, e.g., using Insertable Streams */
	GList *viewers;				/* List of users watching this recording */
	volatile gint completed;	/* Whether this recording was completed or still going on */
	volatile gint destroyed;	/* Whether this recording has been marked as destroyed */
	janus_refcount ref;			/* Reference counter */
	janus_mutex mutex;			/* Mutex for this recording */
} janus_play_recording;
static GHashTable *recordings = NULL;
static janus_mutex recordings_mutex = JANUS_MUTEX_INITIALIZER;

typedef struct janus_play_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	gboolean active;
	gboolean firefox;		/* We send Firefox users a different kind of FIR */
	janus_play_recording *recording;
	janus_play_frame_packet *aframes;	/* Audio frames (for playout) */
	gboolean opusred;		/* Whether this user supports RED for audio (for playout) */
	janus_rtp_switching_context context;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_play_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_play_session_destroy(janus_play_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_play_session_free(const janus_refcount *session_ref) {
	janus_play_session *session = janus_refcount_containerof(session_ref, janus_play_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session);
}


static void janus_play_recording_destroy(janus_play_recording *recording) {
	if(recording && g_atomic_int_compare_and_exchange(&recording->destroyed, 0, 1))
		janus_refcount_decrease(&recording->ref);
}

static void janus_play_recording_free(const janus_refcount *recording_ref) {
	janus_play_recording *recording = janus_refcount_containerof(recording_ref, janus_play_recording, ref);
	/* This recording can be destroyed, free all the resources */
	g_free(recording->name);
	g_free(recording->date);
	g_free(recording->arc_file);
	g_free(recording->afmtp);
	g_free(recording->offer);
	g_free(recording);
}


static char *recordings_path = NULL;
static void janus_play_update_recordings_list(void);
static void *janus_play_playout_thread(void *data);

/* To make things easier, we use static payload types for viewers (unless it's for G.711 or G.722) */
#define AUDIO_PT		111

/* Helper method to check which codec was used in a specific recording (and if it's end-to-end encrypted) */
static const char *janus_play_parse_codec(const char *dir, const char *filename, char *fmtp, size_t fmtplen,
		uint8_t *audiolevel_ext_id, int *opusred_pt, gboolean *e2ee) {
	if(dir == NULL || filename == NULL)
		return NULL;
	if(e2ee)
		*e2ee = FALSE;
	char source[1024];
	if(strstr(filename, ".mjr"))
		g_snprintf(source, 1024, "%s/%s", dir, filename);
	else
		g_snprintf(source, 1024, "%s/%s.mjr", dir, filename);
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
		return NULL;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);

	/* Pre-parse */
	JANUS_LOG(LOG_VERB, "Pre-parsing file %s to generate ordered index...\n", source);
	gboolean parsed_header = FALSE;
	int bytes = 0;
	long offset = 0;
	uint16_t len = 0;
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	/* Let's look for timestamp resets first */
	while(offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			fclose(file);
			return NULL;
		}
		if(prebuffer[1] == 'E') {
			/* Either the old .mjr format header ('MEETECHO' header followed by 'audio' or 'video'), or a frame */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len == 5 && !parsed_header) {
				/* This is the main header */
				parsed_header = TRUE;
				bytes = fread(prebuffer, sizeof(char), 5, file);
				if(prebuffer[0] == 'a') {
					JANUS_LOG(LOG_VERB, "This is an old audio recording, assuming Opus\n");
					fclose(file);
					return "opus";
				}
			}
			JANUS_LOG(LOG_WARN, "Unsupported recording media type...\n");
			fclose(file);
			return NULL;
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len > 0 && !parsed_header) {
				/* This is the info header */
				bytes = fread(prebuffer, sizeof(char), len, file);
				if(bytes < 0) {
					JANUS_LOG(LOG_ERR, "Error reading from file... %s\n", g_strerror(errno));
					fclose(file);
					return NULL;
				}
				parsed_header = TRUE;
				prebuffer[len] = '\0';
				json_error_t error;
				json_t *info = json_loads(prebuffer, 0, &error);
				if(!info) {
					JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
					JANUS_LOG(LOG_WARN, "Error parsing info header...\n");
					fclose(file);
					return NULL;
				}
				/* Is it audio? */
				json_t *type = json_object_get(info, "t");
				if(!type || !json_is_string(type)) {
					JANUS_LOG(LOG_WARN, "Missing/invalid recording type in info header...\n");
					json_decref(info);
					fclose(file);
					return NULL;
				}
				const char *t = json_string_value(type);
				if(strcasecmp(t, "a") != 0) {
					JANUS_LOG(LOG_WARN, "Unsupported recording type '%s' in info header...\n", t);
					json_decref(info);
					fclose(file);
					return NULL;
				}
				/* Check if the recording is end-to-end encrypted */
				json_t *e = json_object_get(info, "e");
				if(e2ee)
					*e2ee = json_is_true(e);
				/* Any fmtp? */
				json_t *f = json_object_get(info, "f");
				if(f && json_is_string(f) && fmtp && fmtplen > 0)
					g_snprintf(fmtp, fmtplen, "%s", json_string_value(f));
				/* What codec was used? */
				json_t *codec = json_object_get(info, "c");
				if(!codec || !json_is_string(codec)) {
					JANUS_LOG(LOG_WARN, "Missing recording codec in info header...\n");
					json_decref(info);
					fclose(file);
					return NULL;
				}
				/* Is RED in use for audio? */
				*opusred_pt = json_integer_value(json_object_get(info, "or"));
				/* Any RTP extension we care about? */
				json_t *exts = json_object_get(info, "x");
				if(exts) {
					int extid = 0;
					const char *key = NULL, *extmap = NULL;
					json_t *value = NULL;
					json_object_foreach(exts, key, value) {
						if(key == NULL || value == NULL || !json_is_string(value))
							continue;
						extid = atoi(key);
						extmap = json_string_value(value);
						if(!strcasecmp(extmap, JANUS_RTP_EXTMAP_AUDIO_LEVEL) && audiolevel_ext_id != NULL)
							*audiolevel_ext_id = extid;
					}
				}
				const char *c = json_string_value(codec);
				const char *mcodec = janus_sdp_match_preferred_codec(JANUS_SDP_AUDIO, (char *)c);
				if(mcodec != NULL) {
					/* Found! */
					json_decref(info);
					fclose(file);
					return mcodec;
				}
				json_decref(info);
			}
			JANUS_LOG(LOG_WARN, "No codec found...\n");
			fclose(file);
			return NULL;
		} else {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			fclose(file);
			return NULL;
		}
	}
	fclose(file);
	return NULL;
}

/* Helper method to prepare an SDP offer when a recording is available */
static int janus_play_generate_offer(janus_play_recording *rec) {
	if(rec == NULL)
		return -1;
	/* Prepare an SDP offer we'll send to playout viewers */
	gboolean offer_audio = (rec->arc_file != NULL && rec->acodec != JANUS_AUDIOCODEC_NONE);
	char s_name[100];
	g_snprintf(s_name, sizeof(s_name), "Recording %"SCNu64, rec->id);
	guint8 mid_ext_id = 1;
	while(mid_ext_id == rec->audiolevel_ext_id)
		mid_ext_id++;
	janus_sdp *offer = janus_sdp_generate_offer(
		s_name, "1.1.1.1",
		JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
			JANUS_SDP_OA_ENABLED, offer_audio,
			JANUS_SDP_OA_CODEC, janus_audiocodec_name(rec->acodec),
			JANUS_SDP_OA_PT, rec->audio_pt,
			JANUS_SDP_OA_OPUSRED_PT, rec->opusred_pt > 0 ? rec->opusred_pt : 0,
			JANUS_SDP_OA_FMTP, rec->afmtp,
			JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDONLY,
			JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_MID, mid_ext_id,
			JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_AUDIO_LEVEL, rec->audiolevel_ext_id,
		JANUS_SDP_OA_DONE);
	g_free(rec->offer);
	rec->offer = janus_sdp_write(offer);
	janus_sdp_destroy(offer);
	return 0;
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
	recordings = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_play_recording_destroy);
	janus_play_update_recordings_list();

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
	g_hash_table_destroy(recordings);
	recordings = NULL;
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
	janus_play_session *session = g_malloc0(sizeof(janus_play_session));
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
		json_object_set_new(info, "recording_id", json_integer(session->recording->id));
		json_object_set_new(info, "recording_name", json_string(session->recording->name));
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
	json_t *request = json_object_get(root, "request");
	/* Some requests ('create' and 'destroy') can be handled synchronously */
	const char *request_text = json_string_value(request);
	if(!strcasecmp(request_text, "configure")) {
		response = json_object();
		json_object_set_new(response, "play", json_string("configure"));
		json_object_set_new(response, "status", json_string("ok"));
		/* Return a success, and also let the client be aware of what changed, to allow crosschecks */
		json_t *settings = json_object();
		json_object_set_new(response, "settings", settings);
		goto plugin_response;
	} else if(!strcasecmp(request_text, "play") || !strcasecmp(request_text, "start") || !strcasecmp(request_text, "stop")) {
		/* These messages are handled asynchronously */
		janus_play_message *msg = g_malloc(sizeof(janus_play_message));
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
	json_t *request = json_object_get(message, "request");
	const char *request_text = json_string_value(request);

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
		msg = g_async_queue_pop(messages);
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
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		json_t *result = NULL;
		char *sdp = NULL;
		gboolean sdp_update = FALSE;
		if(json_object_get(msg->jsep, "update") != NULL)
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
		gboolean e2ee = json_is_true(json_object_get(msg->jsep, "e2ee"));
		const char *filename_text = NULL;
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
			guint64 id_value = 0;
			janus_play_recording *rec = NULL;
			const char *warning = NULL;
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
				id_value = rec->id;
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
			json_t *id = json_object_get(root, "id");
			id_value = json_integer_value(id);
			/* Look for this recording */
			janus_mutex_lock(&recordings_mutex);
			rec = g_hash_table_lookup(recordings, &id_value);
			if(rec != NULL)
				janus_refcount_increase(&rec->ref);
			janus_mutex_unlock(&recordings_mutex);
			if(rec == NULL || rec->offer == NULL || g_atomic_int_get(&rec->destroyed)) {
				if(rec != NULL)
					janus_refcount_decrease(&rec->ref);
				JANUS_LOG(LOG_ERR, "No such recording\n");
				error_code = JANUS_PLAY_ERROR_NOT_FOUND;
				g_snprintf(error_cause, 512, "No such recording");
				goto error;
			}
			/* Access the frames */
			if(rec->arc_file) {
				session->aframes = janus_play_get_frames(recordings_path, rec->arc_file);
				if(session->aframes == NULL) {
					JANUS_LOG(LOG_WARN, "Error opening audio recording, trying to go on anyway\n");
					warning = "Broken audio file, playing video only";
				}
			}
			if(session->aframes == NULL) {
				error_code = JANUS_PLAY_ERROR_INVALID_RECORDING;
				g_snprintf(error_cause, 512, "Error opening recording files");
				goto error;
			}
			if(rec->opusred_pt > 0)
				session->opusred = TRUE;	/* Assume the user does support RED, if it's in the recording */
			session->recording = rec;
			rec->viewers = g_list_append(rec->viewers, session);
			e2ee = rec->e2ee;
			/* Send this viewer the prepared offer  */
			sdp = g_strdup(rec->offer);
playdone:
			JANUS_LOG(LOG_VERB, "Going to offer this SDP:\n%s\n", sdp);
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string(sdp_update ? "restarting" : "preparing"));
			json_object_set_new(result, "id", json_integer(id_value));
			if(warning)
				json_object_set_new(result, "warning", json_string(warning));
			/* Also notify event handlers */
			if(!sdp_update && notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("playout"));
				json_object_set_new(info, "id", json_integer(id_value));
				json_object_set_new(info, "audio", session->aframes ? json_true() : json_false());
				gateway->notify_event(&janus_play_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "start")) {
			if(!session->aframes) {
				JANUS_LOG(LOG_ERR, "Not a playout session, can't start\n");
				error_code = JANUS_PLAY_ERROR_INVALID_STATE;
				g_snprintf(error_cause, 512, "Not a playout session, can't start");
				goto error;
			}
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
				json_object_set_new(info, "id", json_integer(session->recording->id));
				gateway->notify_event(&janus_play_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "stop")) {
			/* Done! */
			result = json_object();
			json_object_set_new(result, "status", json_string("stopped"));
			if(session->recording) {
				json_object_set_new(result, "id", json_integer(session->recording->id));
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("stopped"));
					if(session->recording)
						json_object_set_new(info, "id", json_integer(session->recording->id));
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
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
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

void janus_play_update_recordings_list(void) {
	if(recordings_path == NULL)
		return;
	JANUS_LOG(LOG_VERB, "Updating recordings list in %s\n", recordings_path);
	janus_mutex_lock(&recordings_mutex);
	/* First of all, let's keep track of which recordings are currently available */
	GList *old_recordings = NULL;
	if(recordings != NULL && g_hash_table_size(recordings) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, recordings);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_play_recording *rec = value;
			if(rec) {
				janus_refcount_increase(&rec->ref);
				old_recordings = g_list_append(old_recordings, &rec->id);
			}
		}
	}
	/* Open dir */
	DIR *dir = opendir(recordings_path);
	if(!dir) {
		JANUS_LOG(LOG_ERR, "Couldn't open folder...\n");
		g_list_free(old_recordings);
		janus_mutex_unlock(&recordings_mutex);
		return;
	}
	struct dirent *recent = NULL;
	char recpath[1024];
	while((recent = readdir(dir))) {
		int len = strlen(recent->d_name);
		if(len < 4)
			continue;
		if(strcasecmp(recent->d_name+len-4, ".nfo"))
			continue;
		JANUS_LOG(LOG_VERB, "Importing recording '%s'...\n", recent->d_name);
		memset(recpath, 0, 1024);
		g_snprintf(recpath, 1024, "%s/%s", recordings_path, recent->d_name);
		janus_config *nfo = janus_config_parse(recpath);
		if(nfo == NULL) {
			JANUS_LOG(LOG_ERR, "Invalid recording '%s'...\n", recent->d_name);
			continue;
		}
		GList *cl = janus_config_get_categories(nfo, NULL);
		if(cl == NULL || cl->data == NULL) {
			JANUS_LOG(LOG_WARN, "No recording info in '%s', skipping...\n", recent->d_name);
			janus_config_destroy(nfo);
			continue;
		}
		janus_config_category *cat = (janus_config_category *)cl->data;
		guint64 id = g_ascii_strtoull(cat->name, NULL, 0);
		if(id == 0) {
			JANUS_LOG(LOG_WARN, "Invalid ID, skipping...\n");
			g_list_free(cl);
			janus_config_destroy(nfo);
			continue;
		}
		janus_play_recording *rec = g_hash_table_lookup(recordings, &id);
		if(rec != NULL) {
			JANUS_LOG(LOG_VERB, "Skipping recording with ID %"SCNu64", it's already in the list...\n", id);
			g_list_free(cl);
			janus_config_destroy(nfo);
			/* Mark that we updated this recording */
			old_recordings = g_list_remove(old_recordings, &rec->id);
			janus_refcount_decrease(&rec->ref);
			continue;
		}
		janus_config_item *name = janus_config_get(nfo, cat, janus_config_type_item, "name");
		janus_config_item *date = janus_config_get(nfo, cat, janus_config_type_item, "date");
		janus_config_item *audio = janus_config_get(nfo, cat, janus_config_type_item, "audio");
		if(!name || !name->value || strlen(name->value) == 0 || !date || !date->value || strlen(date->value) == 0) {
			JANUS_LOG(LOG_WARN, "Invalid info for recording %"SCNu64", skipping...\n", id);
			g_list_free(cl);
			janus_config_destroy(nfo);
			continue;
		}
		if((!audio || !audio->value)) {
			JANUS_LOG(LOG_WARN, "No audio in recording %"SCNu64", skipping...\n", id);
			janus_config_destroy(nfo);
			continue;
		}
		rec = g_malloc0(sizeof(janus_play_recording));
		rec->id = id;
		rec->name = g_strdup(name->value);
		rec->date = g_strdup(date->value);
		if(audio && audio->value) {
			rec->arc_file = g_strdup(audio->value);
			char *ext = strstr(rec->arc_file, ".mjr");
			if(ext != NULL)
				*ext = '\0';
			/* Check which codec is in this recording (and if it's end-to-end encrypted) */
			gboolean e2ee = FALSE;
			char fmtp[256];
			fmtp[0] = '\0';
			rec->acodec = janus_audiocodec_from_name(janus_play_parse_codec(recordings_path,
				rec->arc_file, fmtp, sizeof(fmtp), &rec->audiolevel_ext_id, &rec->opusred_pt, &e2ee));
			if(strlen(fmtp) > 0)
				rec->afmtp = g_strdup(fmtp);
			if(e2ee)
				rec->e2ee = TRUE;
		}
		rec->audio_pt = AUDIO_PT;
		if(rec->opusred_pt > 0 && rec->audio_pt == rec->opusred_pt)
			rec->audio_pt++;
		if(rec->acodec != JANUS_AUDIOCODEC_NONE) {
			/* Some audio codecs have a fixed payload type that we can't mess with */
			if(rec->acodec == JANUS_AUDIOCODEC_PCMU)
				rec->audio_pt = 0;
			else if(rec->acodec == JANUS_AUDIOCODEC_PCMA)
				rec->audio_pt = 8;
			else if(rec->acodec == JANUS_AUDIOCODEC_G722)
				rec->audio_pt = 9;
		}
		rec->viewers = NULL;
		if(janus_play_generate_offer(rec) < 0) {
			JANUS_LOG(LOG_WARN, "Could not generate offer for recording %"SCNu64"...\n", rec->id);
		}
		g_atomic_int_set(&rec->destroyed, 0);
		g_atomic_int_set(&rec->completed, 1);
		janus_refcount_init(&rec->ref, janus_play_recording_free);
		janus_mutex_init(&rec->mutex);

		g_list_free(cl);
		janus_config_destroy(nfo);

		/* Add to the list of recordings */
		g_hash_table_insert(recordings, janus_uint64_dup(rec->id), rec);
	}
	closedir(dir);
	/* Now let's check if any of the previously existing recordings was removed */
	if(old_recordings != NULL) {
		while(old_recordings != NULL) {
			guint64 id = *((guint64 *)old_recordings->data);
			JANUS_LOG(LOG_VERB, "Recording %"SCNu64" is not available anymore, removing...\n", id);
			janus_play_recording *old_rec = g_hash_table_lookup(recordings, &id);
			if(old_rec != NULL) {
				/* Remove it */
				g_hash_table_remove(recordings, &id);
				janus_refcount_decrease(&old_rec->ref);
			}
			old_recordings = old_recordings->next;
		}
		g_list_free(old_recordings);
	}
	janus_mutex_unlock(&recordings_mutex);
}

janus_play_frame_packet *janus_play_get_frames(const char *dir, const char *filename) {
	if(!dir || !filename)
		return NULL;
	/* Open the file */
	char source[1024];
	if(strstr(filename, ".mjr"))
		g_snprintf(source, 1024, "%s/%s", dir, filename);
	else
		g_snprintf(source, 1024, "%s/%s.mjr", dir, filename);
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
		return NULL;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	JANUS_LOG(LOG_VERB, "File is %zu bytes\n", fsize);

	/* Pre-parse */
	JANUS_LOG(LOG_VERB, "Pre-parsing file %s to generate ordered index...\n", source);
	gboolean parsed_header = FALSE;
	int bytes = 0;
	long offset = 0;
	uint16_t len = 0, count = 0;
	uint32_t first_ts = 0, last_ts = 0, reset = 0;	/* To handle whether there's a timestamp reset in the recording */
	int audio = 0;
	gint64 c_time = 0, w_time = 0;
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	/* Let's look for timestamp resets first */
	while(offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			fclose(file);
			return NULL;
		}
		if(prebuffer[1] == 'E') {
			/* Either the old .mjr format header ('MEETECHO' header followed by 'audio' or 'video'), or a frame */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len == 5 && !parsed_header) {
				/* This is the main header */
				parsed_header = TRUE;
				JANUS_LOG(LOG_VERB, "Old .mjr header format\n");
				bytes = fread(prebuffer, sizeof(char), 5, file);
				if(prebuffer[0] == 'a') {
					JANUS_LOG(LOG_INFO, "This is an old audio recording, assuming Opus\n");
					audio = 1;
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported recording media type...\n");
					fclose(file);
					return NULL;
				}
				offset += len;
				continue;
			} else if(len < 12) {
				/* Not RTP, skip */
				JANUS_LOG(LOG_VERB, "Skipping packet (not RTP?)\n");
				offset += len;
				continue;
			}
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format, the header may contain useful info */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len > 0 && !parsed_header) {
				/* This is the info header */
				JANUS_LOG(LOG_VERB, "New .mjr header format\n");
				bytes = fread(prebuffer, sizeof(char), len, file);
				if(bytes < 0) {
					JANUS_LOG(LOG_ERR, "Error reading from file... %s\n", g_strerror(errno));
					fclose(file);
					return NULL;
				}
				parsed_header = TRUE;
				prebuffer[len] = '\0';
				json_error_t error;
				json_t *info = json_loads(prebuffer, 0, &error);
				if(!info) {
					JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
					JANUS_LOG(LOG_WARN, "Error parsing info header...\n");
					fclose(file);
					return NULL;
				}
				/* Is it audio? */
				json_t *type = json_object_get(info, "t");
				if(!type || !json_is_string(type)) {
					JANUS_LOG(LOG_WARN, "Missing/invalid recording type in info header...\n");
					json_decref(info);
					fclose(file);
					return NULL;
				}
				const char *t = json_string_value(type);
				if(!strcasecmp(t, "a")) {
					audio = 1;
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported recording type '%s' in info header...\n", t);
					json_decref(info);
					fclose(file);
					return NULL;
				}
				/* What codec was used? */
				json_t *codec = json_object_get(info, "c");
				if(!codec || !json_is_string(codec)) {
					JANUS_LOG(LOG_WARN, "Missing recording codec in info header...\n");
					json_decref(info);
					fclose(file);
					return NULL;
				}
				const char *c = json_string_value(codec);
				/* When was the file created? */
				json_t *created = json_object_get(info, "s");
				if(!created || !json_is_integer(created)) {
					JANUS_LOG(LOG_WARN, "Missing recording created time in info header...\n");
					json_decref(info);
					fclose(file);
					return NULL;
				}
				c_time = json_integer_value(created);
				/* When was the first frame written? */
				json_t *written = json_object_get(info, "u");
				if(!written || !json_is_integer(written)) {
					JANUS_LOG(LOG_WARN, "Missing recording written time in info header...\n");
					json_decref(info);
					fclose(file);
					return NULL;
				}
				w_time = json_integer_value(created);
				/* Summary */
				JANUS_LOG(LOG_VERB, "This is %s recording:\n", "an audio");
				JANUS_LOG(LOG_VERB, "  -- Codec:   %s\n", c);
				JANUS_LOG(LOG_VERB, "  -- Created: %"SCNi64"\n", c_time);
				JANUS_LOG(LOG_VERB, "  -- Written: %"SCNi64"\n", w_time);
				json_decref(info);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			fclose(file);
			return NULL;
		}
		/* Only read RTP header */
		if(audio) {
			bytes = fread(prebuffer, sizeof(char), 16, file);
			janus_rtp_header *rtp = (janus_rtp_header *)prebuffer;
			if(last_ts == 0) {
				first_ts = ntohl(rtp->timestamp);
				if(first_ts > 1000*1000)	/* Just used to check whether a packet is pre- or post-reset */
					first_ts -= 1000*1000;
			} else {
				if(ntohl(rtp->timestamp) < last_ts) {
					/* The new timestamp is smaller than the next one, is it a timestamp reset or simply out of order? */
					if(last_ts-ntohl(rtp->timestamp) > 2*1000*1000*1000) {
						reset = ntohl(rtp->timestamp);
						JANUS_LOG(LOG_VERB, "Timestamp reset: %"SCNu32"\n", reset);
					}
				} else if(ntohl(rtp->timestamp) < reset) {
					JANUS_LOG(LOG_VERB, "Updating timestamp reset: %"SCNu32" (was %"SCNu32")\n", ntohl(rtp->timestamp), reset);
					reset = ntohl(rtp->timestamp);
				}
			}
			last_ts = ntohl(rtp->timestamp);
		}
		/* Skip data for now */
		offset += len;
	}
	/* Now let's parse the frames and order them */
	offset = 0;
	janus_play_frame_packet *list = NULL, *last = NULL;
	while(offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		prebuffer[8] = '\0';
		JANUS_LOG(LOG_HUGE, "Header: %s\n", prebuffer);
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		JANUS_LOG(LOG_HUGE, "  -- Length: %"SCNu16"\n", len);
		offset += 2;
		if(prebuffer[1] == 'J' || len < 12) {
			/* Not RTP, skip */
			JANUS_LOG(LOG_HUGE, "  -- Not RTP, skipping\n");
			offset += len;
			continue;
		}

		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), 16, file);
		if(bytes < 0) {
			JANUS_LOG(LOG_WARN, "Error reading RTP header, stopping here...\n");
			break;
		}
		janus_rtp_header *rtp = (janus_rtp_header *)prebuffer;
		JANUS_LOG(LOG_HUGE, "  -- RTP packet (ssrc=%"SCNu32", pt=%"SCNu16", ext=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		/* Generate frame packet and insert in the ordered list */
		janus_play_frame_packet *p = g_malloc(sizeof(janus_play_frame_packet));
		p->seq = ntohs(rtp->seq_number);
		if(reset == 0) {
			/* Simple enough... */
			p->ts = ntohl(rtp->timestamp);
		} else {
			/* Is this packet pre- or post-reset? */
			if(ntohl(rtp->timestamp) > first_ts) {
				/* Pre-reset... */
				p->ts = ntohl(rtp->timestamp);
			} else {
				/* Post-reset... */
				uint64_t max32 = UINT32_MAX;
				max32++;
				p->ts = max32+ntohl(rtp->timestamp);
			}
		}
		p->len = len;
		p->offset = offset;
		p->next = NULL;
		p->prev = NULL;
		if(list == NULL) {
			/* First element becomes the list itself (and the last item), at least for now */
			list = p;
			last = p;
		} else {
			/* Check where we should insert this, starting from the end */
			int added = 0;
			janus_play_frame_packet *tmp = last;
			while(tmp) {
				if(tmp->ts < p->ts) {
					/* The new timestamp is greater than the last one we have, append */
					added = 1;
					if(tmp->next != NULL) {
						/* We're inserting */
						tmp->next->prev = p;
						p->next = tmp->next;
					} else {
						/* Update the last packet */
						last = p;
					}
					tmp->next = p;
					p->prev = tmp;
					break;
				} else if(tmp->ts == p->ts) {
					/* Same timestamp, check the sequence number */
					if(tmp->seq < p->seq && (abs(tmp->seq - p->seq) < 10000)) {
						/* The new sequence number is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq > p->seq && (abs(tmp->seq - p->seq) > 10000)) {
						/* The new sequence number (resetted) is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					}
				}
				/* If either the timestamp ot the sequence number we just got is smaller, keep going back */
				tmp = tmp->prev;
			}
			if(!added) {
				/* We reached the start */
				p->next = list;
				list->prev = p;
				list = p;
			}
		}
		/* Skip data for now */
		offset += len;
		count++;
	}

	JANUS_LOG(LOG_VERB, "Counted %"SCNu16" RTP packets\n", count);
	janus_play_frame_packet *tmp = list;
	count = 0;
	while(tmp) {
		count++;
		JANUS_LOG(LOG_HUGE, "[%10lu][%4d] seq=%"SCNu16", ts=%"SCNu64"\n", tmp->offset, tmp->len, tmp->seq, tmp->ts);
		tmp = tmp->next;
	}
	JANUS_LOG(LOG_VERB, "Counted %"SCNu16" frame packets\n", count);

	/* Done! */
	fclose(file);
	return list;
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
	if(!session->aframes) {
		janus_refcount_decrease(&rec->ref);
		janus_refcount_decrease(&session->ref);
		JANUS_LOG(LOG_ERR, "No audio frames, can't start playout thread...\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Joining playout thread\n");
	/* Open the files */
	FILE *afile = NULL;
	if(session->aframes) {
		if(rec->arc_file == NULL) {
			janus_refcount_decrease(&rec->ref);
			janus_refcount_decrease(&session->ref);
			JANUS_LOG(LOG_ERR, "The recording session contains some audio packets but seems to lack a recording file name\n");
			g_thread_unref(g_thread_self());
			return NULL;
		}
		char source[1024];
		if(strstr(rec->arc_file, ".mjr"))
			g_snprintf(source, 1024, "%s/%s", recordings_path, rec->arc_file);
		else
			g_snprintf(source, 1024, "%s/%s.mjr", recordings_path, rec->arc_file);
		afile = fopen(source, "rb");
		if(afile == NULL) {
			janus_refcount_decrease(&rec->ref);
			janus_refcount_decrease(&session->ref);
			JANUS_LOG(LOG_ERR, "Could not open audio file %s, can't start playout thread...\n", source);
			g_thread_unref(g_thread_self());
			return NULL;
		}
	}
	/* Timer */
	gboolean asent = FALSE;
	struct timeval now, abefore;
	time_t d_s, d_us;
	gettimeofday(&now, NULL);
	gettimeofday(&abefore, NULL);

	janus_play_frame_packet *audio = session->aframes;
	char *buffer = g_malloc0(1500);
	int bytes = 0;
	int64_t ts_diff = 0, passed = 0;

	int audio_pt = session->recording->audio_pt;

	int akhz = 48;
	if(audio_pt == 0 || audio_pt == 8 || audio_pt == 9)
		akhz = 8;

	while(!g_atomic_int_get(&session->destroyed) && session->active
			&& !g_atomic_int_get(&rec->destroyed) && audio) {
		if(!asent) {
			/* We skipped the last round, so sleep a bit (5ms) */
			g_usleep(5000);
		}
		asent = FALSE;
		if(audio) {
			if(audio == session->aframes) {
				/* First packet, send now */
				fseek(afile, audio->offset, SEEK_SET);
				bytes = fread(buffer, sizeof(char), audio->len, afile);
				if(bytes != audio->len)
					JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, audio->len);
				/* Update payload type */
				janus_rtp_header *rtp = (janus_rtp_header *)buffer;
				if(rec->opusred_pt == 0 || rtp->type != rec->opusred_pt)
					rtp->type = audio_pt;
				/* If the recording contains RED but the user doesn't support it, only use the primary data */
				if(rec->opusred_pt > 0 && rtp->type == rec->opusred_pt && !session->opusred) {
					int plen = 0;
					char *payload = janus_rtp_payload(buffer, bytes, &plen);
					if(payload && plen > 0) {
						GList *blocks = janus_red_parse_blocks(payload, plen);
						if(blocks != NULL) {
							/* Copy the last block (primary data) to the RTP payload */
							GList *last = g_list_last(blocks);
							janus_red_block *rb = (janus_red_block *)(last ? last->data : NULL);
							if(rb && rb->data && rb->length > 0) {
								rtp->type = audio_pt;
								bytes -= (plen - rb->length);
								memmove(payload, rb->data, rb->length);
							}
							g_list_free_full(blocks, (GDestroyNotify)g_free);
						}
					}
				}
				janus_plugin_rtp prtp = { .mindex = -1, .video = FALSE, .buffer = (char *)buffer, .length = bytes };
				janus_plugin_rtp_extensions_reset(&prtp.extensions);
				gateway->relay_rtp(session->handle, &prtp);
				gettimeofday(&now, NULL);
				abefore.tv_sec = now.tv_sec;
				abefore.tv_usec = now.tv_usec;
				asent = TRUE;
				audio = audio->next;
			} else {
				/* What's the timestamp skip from the previous packet? */
				ts_diff = audio->ts - audio->prev->ts;
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
				if(passed < (ts_diff-5000)) {
					asent = FALSE;
				} else {
					/* Update the reference time */
					abefore.tv_usec += ts_diff%1000000;
					if(abefore.tv_usec > 1000000) {
						abefore.tv_sec++;
						abefore.tv_usec -= 1000000;
					}
					if(ts_diff/1000000 > 0) {
						abefore.tv_sec += ts_diff/1000000;
						abefore.tv_usec -= ts_diff/1000000;
					}
					/* Send now */
					fseek(afile, audio->offset, SEEK_SET);
					bytes = fread(buffer, sizeof(char), audio->len, afile);
					if(bytes != audio->len)
						JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, audio->len);
					/* Update payload type */
					janus_rtp_header *rtp = (janus_rtp_header *)buffer;
					if(rec->opusred_pt == 0 || rtp->type != rec->opusred_pt)
						rtp->type = audio_pt;
					/* If the recording contains RED but the user doesn't support it, only use the primary data */
					if(rec->opusred_pt > 0 && rtp->type == rec->opusred_pt && !session->opusred) {
						int plen = 0;
						char *payload = janus_rtp_payload(buffer, bytes, &plen);
						if(payload && plen > 0) {
							GList *blocks = janus_red_parse_blocks(payload, plen);
							if(blocks != NULL) {
								/* Copy the last block (primary data) to the RTP payload */
								GList *last = g_list_last(blocks);
								janus_red_block *rb = (janus_red_block *)(last ? last->data : NULL);
								if(rb && rb->data && rb->length > 0) {
									rtp->type = audio_pt;
									bytes -= (plen - rb->length);
									memmove(payload, rb->data, rb->length);
								}
								g_list_free_full(blocks, (GDestroyNotify)g_free);
							}
						}
					}
					janus_plugin_rtp prtp = { .mindex = -1, .video = FALSE, .buffer = (char *)buffer, .length = bytes };
					janus_plugin_rtp_extensions_reset(&prtp.extensions);
					gateway->relay_rtp(session->handle, &prtp);
					asent = TRUE;
					audio = audio->next;
				}
			}
		}
	}

	g_free(buffer);

	/* Get rid of the indexes */
	janus_play_frame_packet *tmp = NULL;
	audio = session->aframes;
	while(audio) {
		tmp = audio->next;
		g_free(audio);
		audio = tmp;
	}
	session->aframes = NULL;

	if(afile)
		fclose(afile);
	afile = NULL;

	/* Remove from the list of viewers */
	janus_mutex_lock(&rec->mutex);
	rec->viewers = g_list_remove(rec->viewers, session);
	janus_mutex_unlock(&rec->mutex);

	/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
	gateway->close_pc(session->handle);

	janus_refcount_decrease(&rec->ref);
	janus_refcount_decrease(&session->ref);

	JANUS_LOG(LOG_VERB, "Leaving playout thread\n");
	g_thread_unref(g_thread_self());
	return NULL;
}
