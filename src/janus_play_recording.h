#pragma once

#include <glib.h>

extern "C" {
#include "janus/refcount.h"
#include "janus/rtp.h"
}


namespace play {

struct janus_play_recording {
	char* id;					/* Recording unique ID */
	char *arc_file;				/* Audio file name */
	janus_audiocodec acodec;	/* Codec used for audio, if available */
	char *afmtp;				/* Audio fmtp, if any */
	int audio_pt;				/* Payload type to use for audio when playing recordings */
	int opusred_pt;				/* In case RED is used for audio, payload type to use in playback */
	guint8 audiolevel_ext_id;	/* Audio level extmap ID */
	char *offer;				/* The SDP offer that will be sent to watchers */
	gboolean e2ee;				/* Whether media in the recording is encrypted, e.g., using Insertable Streams */
	volatile gint completed;	/* Whether this recording was completed or still going on */
	gint destroyed;	/* Whether this recording has been marked as destroyed */
	janus_refcount ref;			/* Reference counter */
};

janus_play_recording* create_recording(const char* id, const char* file_path);

void janus_play_recording_destroy(janus_play_recording *recording);
void janus_play_recording_free(const janus_refcount *recording_ref);

}
