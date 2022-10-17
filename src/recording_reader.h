#pragma once

#include <stdio.h>

#include <optional>
#include <string>
#include <vector>

struct json_t; // #include <jansson.h>

extern "C" {
#include "janus/rtp.h"
}


namespace play {

struct recording_header
{
	bool audio = false;
	std::string codec;
	std::optional<bool> e2ee;
	std::optional<std::string> fmtp;
	std::optional<int> opusred_pt;
	std::optional<uint8_t> audiolevel_ext_id;
};

struct rtp_header: public ::rtp_header {
	enum {
		MINIMUM_SIZE = 12
	};

	uint16_t seq_number() const
		{ return ntohs(::rtp_header::seq_number); }
	uint32_t rtp_timestamp() const
		{ return ntohl(timestamp); }
};

struct recording_packet
{
	//uint32_t packet_timestamp = 0;
	std::vector<char> packet;

	bool empty() const { return packet.empty(); }

	const rtp_header& header() const
		{ return *reinterpret_cast<const rtp_header*>(packet.data()); }
	rtp_header& header()
		{ return *reinterpret_cast<rtp_header*>(packet.data()); }
};

class recording_reader
{
public:
	enum class read_result {
		success,
		not_opened,
		read_error,
		invalid_format,
		eof,
		eos,
	};

	~recording_reader();

	bool isOpened() const { return _recording_file != nullptr; }
	bool open(const char* path);

	const recording_header& header() const { return _header; }
	recording_header& header() { return _header; }

	const std::optional<rtp_header>& prev_packet_header() const
		{ return _prev_packet_header; }

	const recording_packet& last_packet() const { return _last_packet; }
	recording_packet& last_packet() { return _last_packet; }

	read_result read_next_packet();

	void close();

private:
	bool read_header();
	void parse_header_json(json_t*);
	read_result internal_read_next_packet();

private:
	std::string _recording_file_path;
	FILE* _recording_file = nullptr;
	recording_header _header;
	std::optional<rtp_header> _prev_packet_header;
	recording_packet _tmp_packet;
	recording_packet _last_packet;
	read_result _last_read_result = read_result::not_opened;
};

}
