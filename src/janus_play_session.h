#pragma once

#include <glib.h>

extern "C" {
#include "plugin.h"
#include "janus/rtp.h"
}


namespace play {

struct janus_play_recording;
struct janus_play_frame_packet;

struct janus_play_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	gboolean active;
	gboolean firefox;		/* We send Firefox users a different kind of FIR */
	janus_play_recording *recording;
	gboolean opusred;		/* Whether this user supports RED for audio (for playout) */
	janus_rtp_switching_context context;
	gint hangingup;
	gint destroyed;
	janus_refcount ref;
};

void janus_play_session_destroy(janus_play_session *session);
void janus_play_session_free(const janus_refcount *session_ref);

}
