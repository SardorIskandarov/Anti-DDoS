#ifndef __L2FWD_SERVICE_WIRE_H__
#define __L2FWD_SERVICE_WIRE_H__

/**
 * @file   l2fwd_service_wire.h
 * @brief  Per-service wire protocol v1 — P10 of the big-bang refactor.
 *
 * Locked binary format for the per-tick socket emit. v2 is 468 bytes per
 * message: 32 B header + 432 B payload + 4 B CRC32 footer. All
 * multi-byte integers are big-endian; doubles are IEEE 754 binary64
 * with their bit pattern emitted big-endian.
 *
 * The Python collector consumes this exact format. Any change must bump
 * L2FWD_WIRE_VERSION and ship a paired Python decoder update.
 *
 * v2 (this version) appends a Tier-0 risk vector + dominant-channel section
 * at the payload tail. Every pre-existing section keeps its exact offset;
 * the only growth is at the end (and the CRC/footer offset shifts with the
 * larger payload). buffer[6] bit 0 remains the absolute-floor flag.
 *
 * Header layout (32 B)
 *   off  sz  field
 *    0   4  magic = "L2FW"
 *    4   1  version = 0x02
 *    5   1  msg_type = 0x01 (slot snapshot)
 *    6   1  flags (bit 0 = absolute-floor); 7 reserved
 *    8   8  timestamp_ns (uint64 BE, UNIX epoch ns)
 *   16   2  slot_id (uint16 BE, index into stats array)
 *   18   2  payload_len = 432
 *   20   8  sequence_num (uint64 BE, monotonic per-process)
 *   28   4  reserved2
 *
 * Payload layout (432 B; section offsets relative to payload start)
 *     0..15   Identity        (target_ip, port, proto_kind, is_catchall, profile_name)
 *    16..39   Phase state     (phase, prev_phase, counters)
 *    40..119  Raw counters    (common + outbound)
 *   120..215  Proto counters  (TCP / UDP / ICMP arms)
 *   216..279  Features        (8 doubles)
 *   280..343  Scores          (8 doubles)
 *   344..379  Temporal        (3 windows × 12 B)
 *   380..427  Tier-0 risk vec (6 doubles: pps,bps,fps,burst_pps,burst_bps,burst_fps)
 *   428..431  Dominant chan   (1 B enum + 3 B reserved)
 *
 * Footer (4 B)
 *   464..467  crc32 of bytes [0..463] (Ethernet polynomial 0xEDB88320)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declaration — concrete struct lives in l2fwd_service_stats.h. */
struct service_stats;

/* -------------------------------------------------------------------------
 * Wire-protocol constants
 * ------------------------------------------------------------------------- */
#define L2FWD_WIRE_MAGIC_0      0x4C  /* 'L' */
#define L2FWD_WIRE_MAGIC_1      0x32  /* '2' */
#define L2FWD_WIRE_MAGIC_2      0x46  /* 'F' */
#define L2FWD_WIRE_MAGIC_3      0x57  /* 'W' */
#define L2FWD_WIRE_VERSION      0x02
#define L2FWD_WIRE_MSGTYPE_SNAP 0x01

#define L2FWD_WIRE_MSG_SIZE     468
#define L2FWD_WIRE_HEADER_SIZE   32
#define L2FWD_WIRE_PAYLOAD_SIZE 432
#define L2FWD_WIRE_FOOTER_SIZE    4

/* Header flags byte at buffer offset 6 (was reserved). No version bump:
 * consumers that skip reserved bytes are unaffected, and the byte is inside
 * the CRC region [0..411]. bit 0 = the slot's transition INTO ATTACK was
 * forced by the absolute volumetric floor (raw volume past a hard ceiling,
 * bypassing the gate) rather than the normal gated cascade. buffer[7] and
 * bits 1..7 of buffer[6] remain reserved-zero for future flags. */
#define L2FWD_WIRE_FLAG_ABSOLUTE_FLOOR  0x01

/* Payload section offsets (relative to payload start, not buffer start). */
#define L2FWD_WIRE_PL_IDENTITY_OFF    0
#define L2FWD_WIRE_PL_IDENTITY_SIZE  16
#define L2FWD_WIRE_PL_PHASE_OFF      16
#define L2FWD_WIRE_PL_PHASE_SIZE     24
#define L2FWD_WIRE_PL_COUNTERS_OFF   40
#define L2FWD_WIRE_PL_COUNTERS_SIZE  80
#define L2FWD_WIRE_PL_PROTO_OFF     120
#define L2FWD_WIRE_PL_PROTO_SIZE     96
#define L2FWD_WIRE_PL_FEATURES_OFF  216
#define L2FWD_WIRE_PL_FEATURES_SIZE  64
#define L2FWD_WIRE_PL_SCORES_OFF    280
#define L2FWD_WIRE_PL_SCORES_SIZE    64
#define L2FWD_WIRE_PL_TEMPORAL_OFF  344
#define L2FWD_WIRE_PL_TEMPORAL_SIZE  36
/* v2 tail additions (appended after temporal; existing offsets unchanged). */
#define L2FWD_WIRE_PL_TIER0RISK_OFF 380
#define L2FWD_WIRE_PL_TIER0RISK_SIZE 48   /* 6 doubles BE */
#define L2FWD_WIRE_PL_DOMINANT_OFF  428
#define L2FWD_WIRE_PL_DOMINANT_SIZE   4   /* 1 B enum + 3 B reserved */

/* Verify error codes returned by service_wire_verify(). */
#define L2FWD_WIRE_OK              0
#define L2FWD_WIRE_ERR_SIZE       -1
#define L2FWD_WIRE_ERR_MAGIC      -2
#define L2FWD_WIRE_ERR_VERSION    -3
#define L2FWD_WIRE_ERR_MSGTYPE    -4
#define L2FWD_WIRE_ERR_PAYLOAD    -5
#define L2FWD_WIRE_ERR_CRC        -6

/* -------------------------------------------------------------------------
 * Serialisation API
 * ------------------------------------------------------------------------- */

/**
 * Serialize one slot into a 416-byte wire buffer.
 *
 * @param slot          source slot (read-only). Must be non-NULL and active.
 * @param slot_id       index into the stats array (placed in header @16).
 * @param timestamp_ns  monotonic-ish wall time in nanoseconds.
 * @param sequence_num  monotonic per-process counter for stream ordering.
 * @param buffer        caller-allocated, L2FWD_WIRE_MSG_SIZE bytes.
 *
 * @return  0 on success, -1 if slot/buffer is NULL, -2 if slot is inactive.
 *
 * The buffer is fully overwritten (no partial writes leak old data).
 * The CRC32 footer is computed over the 412-byte header+payload region.
 */
int service_wire_serialize_slot(const struct service_stats *slot,
                                 uint16_t slot_id,
                                 uint64_t timestamp_ns,
                                 uint64_t sequence_num,
                                 uint8_t *buffer);

/**
 * Validate a buffer as a well-formed v1 snapshot message.
 *
 * Returns 0 on valid, or one of L2FWD_WIRE_ERR_* on failure. Each error
 * is distinct so debug tools can pinpoint the issue.
 */
int service_wire_verify(const uint8_t *buffer, size_t size);

/* -------------------------------------------------------------------------
 * Public byte-order + CRC helpers (exported so tests can use them)
 * ------------------------------------------------------------------------- */
uint32_t service_wire_crc32(const uint8_t *data, size_t len);

void service_wire_write_u16   (uint8_t *buf, uint16_t v);
void service_wire_write_u32   (uint8_t *buf, uint32_t v);
void service_wire_write_u64   (uint8_t *buf, uint64_t v);
void service_wire_write_double(uint8_t *buf, double   v);

uint16_t service_wire_read_u16   (const uint8_t *buf);
uint32_t service_wire_read_u32   (const uint8_t *buf);
uint64_t service_wire_read_u64   (const uint8_t *buf);
double   service_wire_read_double(const uint8_t *buf);

#endif /* __L2FWD_SERVICE_WIRE_H__ */
