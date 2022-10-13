#include "janus_play_frame_packet.h"

#include <inttypes.h>
#include <glib.h>
#include <arpa/inet.h>
#include <jansson.h>

extern "C" {
#include "janus/debug.h"
#include "janus/rtp.h"
}


namespace play {

janus_play_frame_packet *janus_play_get_frames(
	const char* recordings_dir,
	const char* file_path)
{
	if(!recordings_dir || !file_path)
		return nullptr;

	if(!g_path_is_absolute(recordings_dir)) {
		JANUS_LOG(LOG_ERR, "Recordings path is not absolute: %s.\n", recordings_dir);
		return nullptr;
	}

	/* Open the file */
	FILE *file = fopen(file_path, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", file_path);
		return NULL;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	JANUS_LOG(LOG_VERB, "File is %zu bytes\n", fsize);

	/* Pre-parse */
	JANUS_LOG(LOG_VERB, "Pre-parsing file %s to generate ordered index...\n", file_path);
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
				JANUS_LOG(LOG_VERB, "  -- Created: %" SCNi64 "\n", c_time);
				JANUS_LOG(LOG_VERB, "  -- Written: %" SCNi64 "\n", w_time);
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
						JANUS_LOG(LOG_VERB, "Timestamp reset: %" SCNu32 "\n", reset);
					}
				} else if(ntohl(rtp->timestamp) < reset) {
					JANUS_LOG(LOG_VERB, "Updating timestamp reset: %" SCNu32 " (was %" SCNu32 ")\n", ntohl(rtp->timestamp), reset);
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
		JANUS_LOG(LOG_HUGE, "  -- Length: %" SCNu16 "\n", len);
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
		JANUS_LOG(LOG_HUGE, "  -- RTP packet (ssrc=%" SCNu32 ", pt=%" SCNu16 ", ext=%" SCNu16 ", seq=%" SCNu16 ", ts=%" SCNu32 ")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		/* Generate frame packet and insert in the ordered list */
		janus_play_frame_packet *p = (janus_play_frame_packet *)g_malloc(sizeof(janus_play_frame_packet));
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

	JANUS_LOG(LOG_VERB, "Counted %" SCNu16 " RTP packets\n", count);
	janus_play_frame_packet *tmp = list;
	count = 0;
	while(tmp) {
		count++;
		JANUS_LOG(LOG_HUGE, "[%10lu][%4d] seq=%" SCNu16 ", ts=%" SCNu64 "\n", tmp->offset, tmp->len, tmp->seq, tmp->ts);
		tmp = tmp->next;
	}
	JANUS_LOG(LOG_VERB, "Counted %" SCNu16 " frame packets\n", count);

	/* Done! */
	fclose(file);
	return list;
}

}
