#include "recording_reader.h"

#include <cassert>
#include <cstdint>

#include <glib.h>
#include <arpa/inet.h>
#include <jansson.h>

extern "C" {
#include "janus/debug.h"
#include "janus/sdp-utils.h"
}

#include "json_ptr.h"


namespace {

class file_pos_resetter
{
public:
	file_pos_resetter(FILE* file, fpos_t* pos) : _file(file), _pos(pos) {}
	~file_pos_resetter() {
		if(_pos)
			fsetpos(_file, _pos);
	}

	void cancel() { _file == nullptr; _pos = nullptr; }

private:
	FILE* _file;
	fpos_t* _pos;
};

}

namespace play {

recording_reader::~recording_reader()
{
	close();
}

bool recording_reader::open(const char* recording_path)
{
	assert(!isOpened());
	close();

	_recording_file_path = recording_path;

	_recording_file = fopen(recording_path, "rb");
	if(!_recording_file) {
		JANUS_LOG(LOG_ERR, "Can't open recording %s\n", recording_path);
		return false;
	}

	if(!read_header()) {
		close();
		return false;
	}

	return true;
}

void recording_reader::close()
{
	_recording_file_path.clear();

	if(_recording_file) {
		fclose(_recording_file);
		_recording_file = nullptr;
	}

	_header = recording_header();

	_prev_packet_header.reset();
	_last_packet = recording_packet();

	_last_read_result = read_result::not_opened;
}

bool recording_reader::read_header()
{
	if(!_recording_file)
		return false;

	const char header_prefix[] = "MJR00002";
	char prefix_buffer[sizeof(header_prefix - 1)];

	size_t read = fread(prefix_buffer, sizeof(prefix_buffer), 1, _recording_file);
	if(!read)
		return false;

	if(0 != memcmp(header_prefix, prefix_buffer, sizeof(prefix_buffer)))
		return false;

	uint16_t block_length;
	read = fread(&block_length, sizeof(block_length), 1, _recording_file);
	if(!read)
		return false;
	block_length = ntohs(block_length);

	char json_buffer[block_length];
	read = fread(json_buffer, sizeof(json_buffer), 1, _recording_file);
	if(!read)
		return false;

	json_error_t json_error;
	json_t* header_json = json_loadb(json_buffer, sizeof(json_buffer), 0, &json_error);
	if(!header_json) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", json_error.line, json_error.text);
		JANUS_LOG(LOG_WARN, "Error parsing info header...\n");
		return false;
	}

	parse_header_json(json_ptr(header_json).get());

	return true;
}

void recording_reader::parse_header_json(json_t* header_json)
{
	recording_header header;

	/* Is it audio? */
	json_t *type = json_object_get(header_json, "t");
	if(type && json_is_string(type) && !strcasecmp(json_string_value(type), "a")) {
		header.audio = true;
	}

	/* Check if the recording is end-to-end encrypted */
	json_t *e = json_object_get(header_json, "e");
	if(e && json_is_boolean(e))
		header.e2ee = json_is_true(e);

	/* Any fmtp? */
	json_t *f = json_object_get(header_json, "f");
	if(f && json_is_string(f))
		header.fmtp = json_string_value(f);

	/* What codec was used? */
	json_t *codec = json_object_get(header_json, "c");
	if(codec && json_is_string(codec)) {
		header.codec = json_string_value(codec);
	}

	/* Is RED in use for audio? */
	json_t *opusred_pt = json_object_get(header_json, "or");
	if(opusred_pt && json_is_integer(opusred_pt))
		header.opusred_pt = json_integer_value(opusred_pt);

	/* Any RTP extension we care about? */
	json_t *exts = json_object_get(header_json, "x");
	if(exts) {
		const char *key = NULL, *extmap = NULL;
		json_t *value = NULL;
		json_object_foreach(exts, key, value) {
			if(key == NULL || value == NULL || !json_is_string(value))
				continue;
			const int extid = atoi(key);
			extmap = json_string_value(value);
			if(!strcasecmp(extmap, JANUS_RTP_EXTMAP_AUDIO_LEVEL))
				header.audiolevel_ext_id = extid;
		}
	}

	_header = header;
}

recording_reader::read_result recording_reader::internal_read_next_packet()
{
	if(!_recording_file)
		return read_result::not_opened;

	fpos_t packet_begin_pos;
	if(0 != fgetpos(_recording_file, &packet_begin_pos)) {
		assert(false);
		return read_result::read_error;
	}

	file_pos_resetter pos_reset(_recording_file, &packet_begin_pos);

	const char eos_prefix[] = "----";
	const char packet_prefix[] = "MEET";
	char prefix_buffer[sizeof(packet_prefix) - 1];

	size_t read = fread(prefix_buffer, sizeof(prefix_buffer), 1, _recording_file);
	if(!read)
		return feof(_recording_file) ? read_result::eof : read_result::read_error;

	if(0 != memcmp(packet_prefix, prefix_buffer, sizeof(prefix_buffer))) {
		if(0 == memcmp(eos_prefix, prefix_buffer, sizeof(prefix_buffer))) {
			pos_reset.cancel();
			return read_result::eos;
		} else {
			return read_result::invalid_format;
		}
	}

	uint32_t recvd_time;
	read = fread(&recvd_time, sizeof(recvd_time), 1, _recording_file);
	if(!read)
		return feof(_recording_file) ? read_result::eof : read_result::read_error;
	recvd_time = ntohs(recvd_time);

	uint16_t block_length;
	read = fread(&block_length, sizeof(block_length), 1, _recording_file);
	if(!read)
		return feof(_recording_file) ? read_result::eof : read_result::read_error;
	block_length = ntohs(block_length);

	if(block_length < rtp_header::MINIMUM_SIZE)
		return read_result::invalid_format;

	_tmp_packet.packet.resize(block_length);
	read = fread(_tmp_packet.packet.data(), block_length, 1, _recording_file);
	if(!read)
		return feof(_recording_file) ? read_result::eof : read_result::read_error;

	pos_reset.cancel();

	if(!_last_packet.empty()) {
		_prev_packet_header = _last_packet.header();
	}
	//_last_packet.packet_timestamp = _tmp_packet.packet_timestamp;
	_last_packet.packet.swap(_tmp_packet.packet);

	return read_result::success;
}

recording_reader::read_result recording_reader::read_next_packet()
{
	if(_last_read_result == read_result::eof)
		clearerr(_recording_file); // maybe some new data was saved from last read time

	_last_read_result = internal_read_next_packet();

	switch(_last_read_result) {
		case read_result::success:
			break;
		case read_result::not_opened:
			JANUS_LOG(LOG_ERR, "Trying to read from not opened recording file\n");
			break;
		case read_result::read_error:
			JANUS_LOG(LOG_ERR, "Failed to read from \"%s\"\n", _recording_file_path.c_str());
			break;
		case read_result::invalid_format:
			JANUS_LOG(LOG_ERR, "Recording \"%s\" has invalid format\n", _recording_file_path.c_str());
			break;
		case read_result::eof:
			JANUS_LOG(LOG_VERB, "EOF found in \"%s\"\n", _recording_file_path.c_str());
			break;
		case read_result::eos:
			JANUS_LOG(LOG_INFO, "EOS found in \"%s\"\n", _recording_file_path.c_str());
			break;
	}

	return _last_read_result;
}

}
