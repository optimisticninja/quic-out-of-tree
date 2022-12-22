#include "frame.h"

#include <asm-generic/errno-base.h>
#include <linux/byteorder/little_endian.h>
#include <linux/printk.h>

// TODO: An endpoint MUST terminate the connection with error STREAM_STATE_ERROR if it receives a STREAM frame for a locally initiated stream that has not yet been created, or for a send-only stream.

// Variable length integers:
// https://www.rfc-editor.org/rfc/rfc9000.html#integer-encoding Values do not
// need to be encoded on the minimum number of bytes necessary, with the sole
// exception of the Frame Type field; see Section 12.4.
//
// Versions, length of connection IDs in long header packets are described using
// integers but do not use this encoding.
// ALL values are in network byte order (big endian)
u8 read_varint(const u8 *data, ssize_t dsz, union vli_t *out) {
  u8 sz, i;
  __be64 v;

  if (dsz < 1 || dsz > 8) {
    pr_alert("[QUIC]: invalid varint size %lu", dsz);
    return EINVAL;
  }

  // Validate passed data length matches encoded size
  if (dsz != (sz = 1 << (data[0] >> 6))) {
    pr_alert("[QUIC]: encoded size doesn't match data length %u vs %lu", sz,
             dsz);
    return EINVAL;
  }

  // Mask VLI length out of first byte and expand integer
  for (v = data[0] & 0x3f, i = 1; i < sz; v = (v << 8) + data[i++])
    ;

  switch (sz) {
  case 1:
    out->vli6 = v;
    return 0;
  case 2:
    out->vli14 = v;
    break;
  case 4:
    out->vli30 = v;
    break;
  case 8:
    out->vli62 = v;
    break;
  default:
    pr_alert("[QUIC]: variable length integer greater than maximum "
             "permissible size");
  }
  return 0;
}

// Encode VLI from host endianness for testing
u8 write_varint(const u8 *data, ssize_t dsz, union vli_t *out)
{
	
}

// TODO: When a Stream Data field has a length of 0, the offset in the STREAM frame is the offset of the next byte that would be sent.
// TODO: The largest offset delivered on a stream -- the sum of the offset and data length -- cannot exceed 262-1, as it is not possible to provide flow control credit for that data. Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or FLOW_CONTROL_ERROR.
u8 valid_stream_frame(const struct stream_frame_t* frame)
{
	// TODO: better error handling with ERRNO, currently just aggregating error count
	u8 ret = 0;

	// Check 4th bit is set in type
	if (!(frame->type & 0b00001000 >> 3)) {
		pr_alert("[QUIC]: invalid stream frame type: LSB[4] was 0");
		return EINVAL;
	}

	if (frame->type < 0x08 || frame->type > 0x0f) {
		pr_alert("[QUIC]: invalid stream frame type: outside valid range of 0x08..0x0f, found %02x", frame->type);
		ret++;
		return EINVAL;
	}

	return ret;
}

inline u8 initiator(__be64 sid) { return sid & 1; }

inline u8 direction(__be64 sid) { return sid >> 1 & 1; }

// Create stream frame type with enabled features, none are required unless
// ending the stream, then fin must be provided
inline u8 type(u8 off, u8 len, u8 fin)
{
	// 4th-most LSB set requirement in field flags
	return 0b00001000 | off | len | fin;
}

// VLI TESTS
// For example, the eight-byte sequence 0xc2197c5eff14e88c decodes to the
// decimal value 151,288,809,941,952,652; the four-byte sequence 0x9d7f3e7d
// decodes to 494, 878,333; the two-byte sequence 0x7bbd decodes to 15,293; and
// the single byte 0x25 decodes to 37 (as does the two-byte sequence 0x4025).
void test_vli(void) {
  __be64 seq62 = cpu_to_be64(0xc2197c5eff14e88c);
  u64 check62 = 151288809941952652;
  __be32 seq30 = cpu_to_be32(0x9d7f3e7d);
  u32 check30 = 494878333;
  __be16 seq14 = cpu_to_be16(0x7bbd);
  u16 check14 = 15293;
  __be16 seq14_2 = cpu_to_be16(0x4025);
  u16 check14_2 = 37;
  u8 seq6 = 0x25;
  u8 check6 = check14_2;

  union vli_t vli62;
  union vli_t vli30;
  union vli_t vli14;
  union vli_t vli14_2;
  union vli_t vli6;

  // TODO: Should probably check ret value
  read_varint((u8 *)&seq62, sizeof(__be64), &vli62);
  read_varint((u8 *)&seq30, sizeof(__be32), &vli30);
  read_varint((u8 *)&seq14, sizeof(__be16), &vli14);
  read_varint((u8 *)&seq14_2, sizeof(__be16), &vli14_2);
  read_varint((u8 *)&seq6, sizeof(u8), &vli6);

  if (vli62.vli62 != check62) {
    pr_alert("[QUIC]: vli62\t- %llu was not %llu", vli62.vli62, check62);
  }
  if (vli30.vli30 != check30) {
    pr_alert("[QUIC]: vli30\t- %u was not %u", vli30.vli30, check30);
  }
  if (vli14.vli14 != check14) {
    pr_alert("[QUIC]: vli14\t- %u was not %u", vli14.vli14, check14);
  }
  if (vli14_2.vli14 != check14_2) {
    pr_alert("[QUIC]: vli14 (2)\t- %u was not %u", vli14_2.vli14, check14_2);
  }
  if (vli6.vli6 != check6) {
    pr_alert("[QUIC]: vli6\t- %u was not %u", vli6.vli6, check6);
  }
}

void valid_stream_frame_tests(void) 
{
	// VALID frames
	struct stream_frame_t valid_min_none = { // 0x08
		.type = type(FIELD_NONE, FIELD_NONE, FIELD_NONE),
	};
	struct stream_frame_t valid_sf_len = {   // 0x09
		.type = type(FIELD_LEN, FIELD_NONE, FIELD_NONE),
	};
	struct stream_frame_t valid_sf_off = {
		.type = type(FIELD_NONE, FIELD_OFF, FIELD_NONE),
	};
	struct stream_frame_t valid_sf_fin = {
		.type = type(FIELD_NONE, FIELD_NONE, FIELD_FIN),
	};
}
