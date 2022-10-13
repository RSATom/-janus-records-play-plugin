#pragma once

#include <cstdint>


namespace play {

struct janus_play_frame_packet {
	uint16_t seq;	/* RTP Sequence number */
	uint64_t ts;	/* RTP Timestamp */
	int len;		/* Length of the data */
	long offset;	/* Offset of the data in the file */
	struct janus_play_frame_packet *next;
	struct janus_play_frame_packet *prev;
};

janus_play_frame_packet *janus_play_get_frames(const char *dir, const char *filename);

}
