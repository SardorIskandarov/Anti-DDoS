/**
 * @file   l2fwd_service_wire.c
 * @brief  Per-service wire protocol v2 — P10 implementation.
 *
 * See l2fwd_service_wire.h for the locked layout. This module reads from
 * struct service_stats / detection_state / temporal_state / common HLL +
 * CM sketches and produces a 468-byte big-endian message (wire v2). It never
 * mutates any of those structures.
 *
 * The CRC32 polynomial is 0xEDB88320 (Ethernet / zlib / PNG). Table-driven
 * (initialised on first use; benign data race on multi-thread first-touch
 * because the table values are deterministic).
 */

#include "l2fwd_service_wire.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_detection.h"
#include "l2fwd_service_temporal_state.h"
#include "l2fwd_service_features.h"
#include "l2fwd_l2_profile.h"

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>   /* htons, htonl */
#include <endian.h>      /* htobe64, be64toh */

/* -------------------------------------------------------------------------
 * Big-endian byte-order helpers
 *
 * memcpy avoids alignment + strict-aliasing pitfalls. Modern compilers
 * fold these into a single MOV+BSWAP pair, so the readability win is
 * essentially free.
 * ------------------------------------------------------------------------- */

void service_wire_write_u16(uint8_t *buf, uint16_t v) {
    uint16_t be = htons(v);
    memcpy(buf, &be, 2);
}

void service_wire_write_u32(uint8_t *buf, uint32_t v) {
    uint32_t be = htonl(v);
    memcpy(buf, &be, 4);
}

void service_wire_write_u64(uint8_t *buf, uint64_t v) {
    uint64_t be = htobe64(v);
    memcpy(buf, &be, 8);
}

void service_wire_write_double(uint8_t *buf, double v) {
    /* memcpy through uint64_t keeps the bit pattern intact across the
     * htobe64 conversion. The result is IEEE 754 binary64, big-endian. */
    uint64_t bits;
    memcpy(&bits, &v, 8);
    service_wire_write_u64(buf, bits);
}

uint16_t service_wire_read_u16(const uint8_t *buf) {
    uint16_t be;
    memcpy(&be, buf, 2);
    return ntohs(be);
}

uint32_t service_wire_read_u32(const uint8_t *buf) {
    uint32_t be;
    memcpy(&be, buf, 4);
    return ntohl(be);
}

uint64_t service_wire_read_u64(const uint8_t *buf) {
    uint64_t be;
    memcpy(&be, buf, 8);
    return be64toh(be);
}

double service_wire_read_double(const uint8_t *buf) {
    uint64_t bits = service_wire_read_u64(buf);
    double v;
    memcpy(&v, &bits, 8);
    return v;
}

/* -------------------------------------------------------------------------
 * CRC-32 (Ethernet / zlib polynomial 0xEDB88320)
 *
 * Initial value 0xFFFFFFFF, final XOR 0xFFFFFFFF — matches Python's
 * zlib.crc32() so the Python decoder doesn't need its own CRC implementation.
 * ------------------------------------------------------------------------- */

static uint32_t g_crc_table[256];
static int      g_crc_table_initialized = 0;

static void crc_table_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        g_crc_table[i] = c;
    }
    g_crc_table_initialized = 1;
}

uint32_t service_wire_crc32(const uint8_t *data, size_t len) {
    if (!g_crc_table_initialized) crc_table_init();
    uint32_t crc = 0xFFFFFFFFu;
    if (data) {
        for (size_t i = 0; i < len; i++) {
            crc = g_crc_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* -------------------------------------------------------------------------
 * Per-section serialisers.
 *
 * Each takes a pointer to the start of its section in the payload, plus
 * whatever input data it needs. Keeping each section in its own function
 * lets the test harness exercise them independently if needed and keeps
 * service_wire_serialize_slot itself short.
 * ------------------------------------------------------------------------- */

static void write_identity_section(uint8_t *id, const struct service_stats *slot) {
    service_wire_write_u32(id + 0, slot->key.target_ip);
    service_wire_write_u16(id + 4, slot->key.port);
    id[6] = slot->proto_kind;
    id[7] = slot->is_catchall ? 1u : 0u;

    /* profile_name: first 8 bytes, null-padded. Use memcpy via strnlen so
     * we never read past the strncpy-style buffer end if the profile name
     * happens to be exactly 8 chars long (no trailing NUL needed on wire). */
    if (slot->profile && slot->profile->name) {
        size_t n = strnlen(slot->profile->name, 8);
        memcpy(id + 8, slot->profile->name, n);
        /* bytes id+8+n .. id+15 are already zero from the buffer memset */
    }
}

static void write_phase_section(uint8_t *ph,
                                 const struct service_detection_state *det)
{
    if (!det) return;       /* buffer is already zeroed */
    ph[0] = det->phase;
    ph[1] = det->prev_phase;
    /* ph[2..3] reserved */
    service_wire_write_u32(ph +  4, det->warmup_remaining);
    service_wire_write_u32(ph +  8, det->consecutive_attack_windows);
    service_wire_write_u32(ph + 12, det->baseline_freeze_remaining);
    service_wire_write_u32(ph + 16, det->thaw_cooldown_remaining);
    service_wire_write_u32(ph + 20,
        (uint32_t)(det->windows_seen & 0xFFFFFFFFu));
}

static void write_counters_section(uint8_t *c, const struct service_stats *slot) {
    service_wire_write_u64(c +  0, slot->common.inbound_pkts);
    service_wire_write_u64(c +  8, slot->common.inbound_bytes);
    service_wire_write_u64(c + 16, slot->common.off_proto_pkts);
    service_wire_write_u64(c + 24, slot->common.ip_frag_pkts);
    service_wire_write_u64(c + 32, slot->common.ttl_sum);
    service_wire_write_u64(c + 40, slot->common.ttl_sum_sq);
    service_wire_write_u64(c + 48, slot->outbound.out_pkts);
    service_wire_write_u64(c + 56, slot->outbound.out_bytes);
    /* Outbound proto counters are uint64 in the struct, truncated to
     * uint32 on the wire (4 G pkts/sec/proto headroom — far above
     * line rate on any expected NIC). */
    service_wire_write_u32(c + 64, (uint32_t)slot->outbound.out_tcp_pkts);
    service_wire_write_u32(c + 68, (uint32_t)slot->outbound.out_udp_pkts);
    service_wire_write_u32(c + 72, (uint32_t)slot->outbound.out_icmp_pkts);
    /* c + 76..79 reserved (zero) */
}

static void write_proto_section(uint8_t *p, const struct service_stats *slot) {
    /* The 96-byte section accommodates all three proto-arm raw counters
     * laid out at fixed offsets so the Python decoder doesn't have to
     * branch on proto_kind to find a field. Whichever arms aren't
     * applicable to this slot stay zeroed. */
    const struct service_tcp_stats  *t  = NULL;
    const struct service_udp_stats  *u  = NULL;
    const struct service_icmp_stats *ic = NULL;

    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        t = &slot->proto.tcp.stats;
        break;
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        u = &slot->proto.udp.stats;
        break;
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP:
        ic = &slot->proto.icmp.stats;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        t  = &slot->proto.other_catchall.tcp_stats;
        u  = &slot->proto.other_catchall.udp_stats;
        ic = &slot->proto.other_catchall.icmp_stats;
        break;
    default:
        break;
    }

    if (t) {
        service_wire_write_u64(p +  0, t->tcp_pkts);
        service_wire_write_u64(p +  8, t->tcp_bytes);
        service_wire_write_u64(p + 16, t->syn_pkts);
        service_wire_write_u64(p + 24, t->syn_ack_pkts);
        service_wire_write_u64(p + 32, t->fin_ack_pkts);
        service_wire_write_u64(p + 40, t->rst_pkts);
        service_wire_write_u64(p + 48, t->ack_data_pkts);
        service_wire_write_u64(p + 56, t->empty_ack_pkts);
        service_wire_write_u64(p + 64, t->zero_window_pkts);
    }
    if (u) {
        service_wire_write_u64(p + 72, u->udp_pkts);
        service_wire_write_u64(p + 80, u->udp_bytes);
    }
    if (ic) {
        service_wire_write_u64(p + 88, ic->icmp_pkts);
    }
}

static void write_features_section(uint8_t *f, const struct service_stats *slot) {
    double src_ip_card = service_hll_estimate(&slot->common.unique_src_ips);
    double flow_card   = service_hll_estimate(&slot->common.unique_flows);
    double top1        = service_cm_top1_share(
        (uint64_t)slot->common.cm_src_24.top_count,
        slot->common.cm_src_24.total);
    double ent         = service_cm_src_24_entropy(&slot->common.cm_src_24);

    double ttl_mean = 0.0, ttl_stddev = 0.0;
    service_compute_mean_stddev(slot->common.ttl_sum,
                                 slot->common.ttl_sum_sq,
                                 slot->common.inbound_pkts,
                                 &ttl_mean, &ttl_stddev);

    service_wire_write_double(f +  0, src_ip_card);
    service_wire_write_double(f +  8, flow_card);
    service_wire_write_double(f + 16, top1);
    service_wire_write_double(f + 24, ent);
    service_wire_write_double(f + 32, ttl_mean);
    service_wire_write_double(f + 40, ttl_stddev);
    service_wire_write_double(f + 48, slot->common.bw_pps.z_last);
    service_wire_write_double(f + 56, slot->common.bw_bps.z_last);
}

static void write_scores_section(uint8_t *s,
                                  const struct service_detection_state *det)
{
    if (!det) return;
    service_wire_write_double(s +  0, det->last_tier0_score);
    service_wire_write_double(s +  8, det->last_tier1_tcp_score);
    service_wire_write_double(s + 16, det->last_tier1_udp_score);
    service_wire_write_double(s + 24, det->last_tier1_icmp_score);
    service_wire_write_double(s + 32, det->last_tier1_dist_score);
    service_wire_write_double(s + 40, det->last_tier1_l3_score);
    service_wire_write_double(s + 48, det->last_tier1_offproto_score);
    service_wire_write_double(s + 56, det->last_tier1_final_score);
}

/* v2: Tier-0 per-channel risk vector — six doubles, in the order
 * pps, bps, fps, burst_pps, burst_bps, burst_fps. Values already computed and
 * cached by service_scoring_tier0_evaluate(). Leaves the section zeroed when
 * det is NULL (buffer was memset). */
static void write_tier0risk_section(uint8_t *t,
                                    const struct service_detection_state *det)
{
    if (!det) return;
    service_wire_write_double(t +  0, det->last_tier0_risk_pps);
    service_wire_write_double(t +  8, det->last_tier0_risk_bps);
    service_wire_write_double(t + 16, det->last_tier0_risk_fps);
    service_wire_write_double(t + 24, det->last_tier0_risk_burst_pps);
    service_wire_write_double(t + 32, det->last_tier0_risk_burst_bps);
    service_wire_write_double(t + 40, det->last_tier0_risk_burst_fps);
}

static void write_temporal_section(uint8_t *tw,
                                    const struct service_temporal_state *tmp)
{
    if (!tmp) return;
    int max_w = (SERVICE_TEMPORAL_WINDOW_COUNT < 3)
                 ? SERVICE_TEMPORAL_WINDOW_COUNT : 3;
    for (int w = 0; w < max_w; w++) {
        const struct service_temporal_window *win = &tmp->windows[w];
        uint8_t *slot = tw + w * 12;
        service_wire_write_u32(slot + 0,
            (uint32_t)(win->total_pkts & 0xFFFFFFFFu));
        /* peak_pps is a double in the struct (P5); wire format takes
         * the truncated uint32 — sufficient for any single-second peak
         * within line rate. */
        uint32_t peak_u32 = (win->peak_pps > 0.0 && win->peak_pps < 4.29e9)
                             ? (uint32_t)win->peak_pps
                             : 0xFFFFFFFFu;
        service_wire_write_u32(slot + 4, peak_u32);
        service_wire_write_u32(slot + 8, win->attack_seconds);
    }
}

/* -------------------------------------------------------------------------
 * The main entry point
 * ------------------------------------------------------------------------- */

int service_wire_serialize_slot(const struct service_stats *slot,
                                 uint16_t slot_id,
                                 uint64_t timestamp_ns,
                                 uint64_t sequence_num,
                                 uint8_t *buffer)
{
    if (!slot || !buffer)  return -1;
    if (!slot->active)     return -2;

    memset(buffer, 0, L2FWD_WIRE_MSG_SIZE);

    /* --- Header --- */
    buffer[0] = L2FWD_WIRE_MAGIC_0;
    buffer[1] = L2FWD_WIRE_MAGIC_1;
    buffer[2] = L2FWD_WIRE_MAGIC_2;
    buffer[3] = L2FWD_WIRE_MAGIC_3;
    buffer[4] = L2FWD_WIRE_VERSION;
    buffer[5] = L2FWD_WIRE_MSGTYPE_SNAP;
    /* buffer[6] = header flags byte; bit 0 carries the absolute-floor
     * provenance from the detection state. buffer[7] stays reserved-zero.
     * Both are inside the CRC region, so the existing CRC covers them. */
    {
        const struct service_detection_state *fdet =
            (const struct service_detection_state *)slot->detection_state;
        buffer[6] = (fdet && fdet->last_absolute_floor_fired)
                    ? L2FWD_WIRE_FLAG_ABSOLUTE_FLOOR : 0u;
    }
    /* buffer[7] reserved */
    service_wire_write_u64(buffer +  8, timestamp_ns);
    service_wire_write_u16(buffer + 16, slot_id);
    service_wire_write_u16(buffer + 18, L2FWD_WIRE_PAYLOAD_SIZE);
    service_wire_write_u64(buffer + 20, sequence_num);
    /* buffer[28..31] reserved */

    /* --- Payload --- */
    uint8_t *pl = buffer + L2FWD_WIRE_HEADER_SIZE;
    write_identity_section(pl + L2FWD_WIRE_PL_IDENTITY_OFF, slot);
    write_phase_section   (pl + L2FWD_WIRE_PL_PHASE_OFF,
        (const struct service_detection_state *)slot->detection_state);
    write_counters_section(pl + L2FWD_WIRE_PL_COUNTERS_OFF, slot);
    write_proto_section   (pl + L2FWD_WIRE_PL_PROTO_OFF,    slot);
    write_features_section(pl + L2FWD_WIRE_PL_FEATURES_OFF, slot);
    write_scores_section  (pl + L2FWD_WIRE_PL_SCORES_OFF,
        (const struct service_detection_state *)slot->detection_state);
    write_temporal_section(pl + L2FWD_WIRE_PL_TEMPORAL_OFF,
        (const struct service_temporal_state *)slot->temporal_state);

    /* --- v2 tail: Tier-0 risk vector + dominant channel --- */
    {
        const struct service_detection_state *vdet =
            (const struct service_detection_state *)slot->detection_state;
        write_tier0risk_section(pl + L2FWD_WIRE_PL_TIER0RISK_OFF, vdet);
        pl[L2FWD_WIRE_PL_DOMINANT_OFF] = vdet ? vdet->last_dominant_channel : 0u;
        /* DOMINANT_OFF+1..+3 reserved — already zero from the memset. */
    }

    /* --- Footer: CRC32 over the header+payload region [0..463] --- */
    uint32_t crc = service_wire_crc32(
        buffer, L2FWD_WIRE_HEADER_SIZE + L2FWD_WIRE_PAYLOAD_SIZE);
    service_wire_write_u32(
        buffer + L2FWD_WIRE_HEADER_SIZE + L2FWD_WIRE_PAYLOAD_SIZE, crc);

    return 0;
}

/* -------------------------------------------------------------------------
 * Verification
 * ------------------------------------------------------------------------- */

int service_wire_verify(const uint8_t *buffer, size_t size) {
    if (!buffer || size != L2FWD_WIRE_MSG_SIZE)
        return L2FWD_WIRE_ERR_SIZE;
    if (buffer[0] != L2FWD_WIRE_MAGIC_0 ||
        buffer[1] != L2FWD_WIRE_MAGIC_1 ||
        buffer[2] != L2FWD_WIRE_MAGIC_2 ||
        buffer[3] != L2FWD_WIRE_MAGIC_3)
        return L2FWD_WIRE_ERR_MAGIC;
    if (buffer[4] != L2FWD_WIRE_VERSION)        return L2FWD_WIRE_ERR_VERSION;
    if (buffer[5] != L2FWD_WIRE_MSGTYPE_SNAP)   return L2FWD_WIRE_ERR_MSGTYPE;

    uint16_t plen = service_wire_read_u16(buffer + 18);
    if (plen != L2FWD_WIRE_PAYLOAD_SIZE)        return L2FWD_WIRE_ERR_PAYLOAD;

    uint32_t expected_crc = service_wire_read_u32(
        buffer + L2FWD_WIRE_HEADER_SIZE + L2FWD_WIRE_PAYLOAD_SIZE);
    uint32_t actual_crc = service_wire_crc32(
        buffer, L2FWD_WIRE_HEADER_SIZE + L2FWD_WIRE_PAYLOAD_SIZE);
    if (expected_crc != actual_crc)             return L2FWD_WIRE_ERR_CRC;

    return L2FWD_WIRE_OK;
}
