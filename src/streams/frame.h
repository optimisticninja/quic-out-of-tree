#pragma once

#include <linux/types.h>

// LSB of stream ID
enum { INITIATOR_CLIENT, INITIATOR_SERVER };

// 2nd-most LSB of stream ID
enum { DIRECTION_UNI, DIRECTION_BI };

enum stream_frame_type {
	TYPE_PADDING,						// 0x00
	TYPE_PING,							// 0x01
	TYPE_ACK,								// 0x02
	TYPE_ACK_CUMULATIVE,		// 0x03
	TYPE_RESET_STREAM,			// 0x04
	TYPE_STOP_SENDING,			// 0x05
	TYPE_CRYPTO,						// 0x06
	TYPE_NEW_TOKEN,					// 0x07
	// see type(field, field, field) in frame.c for value mapping
	TYPE_STREAM,				 	  // 0x08
	TYPE_STREAM_FIN,			  // 0x09
	TYPE_STREAM_LEN,			  // 0x0a
	TYPE_STREAM_FIN_LEN,	  // 0x0b
	TYPE_STREAM_OFF,			  // 0x0c
	TYPE_STREAM_FIN_OFF,    // 0x0d
	TYPE_STREAM_FIN_LEN_OFF // 0x0f
};

typedef u8 __vli6;
typedef u16 __vli14;
typedef u32 __vli30;
typedef u64 __vli62;

// TODO: Is a union even worth it? More storage for smaller types - macro magic?
union vli_t {
  __vli6 vli6;
  __vli14 vli14;
  __vli30 vli30;
  __vli62 vli62;
};

// Field presence indicator masks, these are encoded in the 3 LSB of stream_frame_t's
// type
enum {
	FIELD_NONE = 0,				// Indicates field is disabled
  FIELD_OFF  = 1 << 2,	// Indicates if Offset field is present, else offset is 0
  FIELD_LEN  = 1 << 1,	// Indicates if Length field is present, else Stream Data
												// extends to the end of packet
  FIELD_FIN = 1					// Indicates the frame marks the end of the stream
};

// TODO: Validate size of stream; the final size of the stream is the sum of the
// offset and the length of this frame.
struct stream_frame_t {
  // TODO: Validate 4th bit is always set
  // TODO: Restrict type 0x08..0x0f (3 LSB)
  // TODO:
  u8 type;
  // TODO: Validate stream ID used ONLY once per connection
  __vli62 sid;
	__vli62 len;
	__vli62 off;
};

// FIXME: Decode LE and BE, this assumes one or the other
u8 read_varint(const u8 *data, ssize_t dsz, union vli_t *out);
u8 valid_stream_frame(const struct stream_frame_t* frame);

void test_vli(void);
