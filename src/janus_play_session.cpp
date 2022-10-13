#include "janus_play_session.h"


namespace play {

void janus_play_session_destroy(janus_play_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

void janus_play_session_free(const janus_refcount *session_ref) {
	janus_play_session *session = janus_refcount_containerof(session_ref, janus_play_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session);
}

}
