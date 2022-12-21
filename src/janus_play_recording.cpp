#include "janus_play_recording.h"

extern "C" {
#include "janus/sdp-utils.h"
}


/* To make things easier, we use static payload types for viewers (unless it's for G.711 or G.722) */
#define AUDIO_PT		111

namespace {

using namespace play;

/* Helper method to prepare an SDP offer when a recording is available */
int janus_play_generate_offer(janus_play_recording *rec) {
	if(rec == NULL)
		return -1;
	/* Prepare an SDP offer we'll send to playout viewers */
	gboolean offer_audio = (rec->arc_file != NULL && rec->acodec != JANUS_AUDIOCODEC_NONE);
	char s_name[100];
	g_snprintf(s_name, sizeof(s_name), "Recording %s", rec->id);
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

/* Helper method to check which codec was used in a specific recording (and if it's end-to-end encrypted) */
const char *janus_play_parse_codec(const char *filename, char *fmtp, size_t fmtplen,
		uint8_t *audiolevel_ext_id, int *opusred_pt, gboolean *e2ee) {
	if(filename == NULL)
		return NULL;
	if(e2ee)
		*e2ee = FALSE;

	FILE *file = fopen(filename, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", filename);
		return NULL;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);

	/* Pre-parse */
	JANUS_LOG(LOG_VERB, "Pre-parsing file %s to generate ordered index...\n", filename);
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

}

namespace play {

janus_play_recording* create_recording(
	const char* id,
	const char* file_path)
{
	janus_play_recording *rec = (janus_play_recording *)g_malloc0(sizeof(janus_play_recording));

	if(file_path) {
		rec->arc_file = g_strdup(file_path);

		/* Check which codec is in this recording (and if it's end-to-end encrypted) */
		gboolean e2ee = FALSE;
		char fmtp[256];
		fmtp[0] = '\0';

		const char* codecName =
			janus_play_parse_codec(
				rec->arc_file,
				fmtp, sizeof(fmtp),
				&rec->audiolevel_ext_id,
				&rec->opusred_pt,
				&e2ee);

		if(!codecName) {
			janus_play_recording_free(&rec->ref);
			return nullptr;
		}

		rec->acodec = janus_audiocodec_from_name(codecName);
		if(strlen(fmtp) > 0)
			rec->afmtp = g_strdup(fmtp);
		if(e2ee)
			rec->e2ee = TRUE;
	}

	rec->id = g_strdup(id);
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

	if(janus_play_generate_offer(rec) < 0) {
		JANUS_LOG(LOG_WARN, "Could not generate offer for recording \"%s\"...\n", rec->id);
	}

	g_atomic_int_set(&rec->destroyed, 0);
	g_atomic_int_set(&rec->completed, 1);
	janus_refcount_init(&rec->ref, janus_play_recording_free);

	return rec;
}


void janus_play_recording_destroy(janus_play_recording *recording) {
	if(recording && g_atomic_int_compare_and_exchange(&recording->destroyed, 0, 1))
		janus_refcount_decrease(&recording->ref);
}

void janus_play_recording_free(const janus_refcount *recording_ref) {
	janus_play_recording *recording = janus_refcount_containerof(recording_ref, janus_play_recording, ref);
	/* This recording can be destroyed, free all the resources */
	g_free(recording->id);
	g_free(recording->arc_file);
	g_free(recording->afmtp);
	g_free(recording->offer);
	g_free(recording);
}

}
