/*
 * l2fwd_l3_bridge.h — Layer 3 V1 per-packet collection bridge (C side)
 *
 * ROLE
 *   Raw collection and export only.  This module has no knowledge of:
 *     - scoring logic          (Python responsibility)
 *     - policy decisions       (Python responsibility)
 *     - Layer 2 detection      (l2fwd_ddos_collector.c responsibility)
 *
 *   The bridge sits between the Layer 2 detection engine and the Python
 *   Layer 3 scoring engine:
 *
 *     L2 collector ──set_attack_state()──► bridge victim table
 *     Hot path     ──collect_src_packet()─► per-source counters
 *     Timer lcore  ──export_and_reset()──► UNIX socket ──► Python layer3_v1.py
 *
 * EXPORTED JSON RECORDS (newline-delimited, over UNIX stream socket)
 *
 *   src_snapshot — one per source IP per window:
 *     {"type":"src_snapshot","dst_ip":"...","src_ip":"...","window_ms":N,
 *      "pkt_count":N,"byte_count":N,"tcp_pkts":N,"syn_pkts":N,
 *      "rst_pkts":N,"ack_only_pkts":N,
 *      "unique_dst_ports":N,"unique_flows":N,"duration_sec":F}
 *
 *   window_end — one per victim per window, after all src_snapshots:
 *     {"type":"window_end","dst_ip":"...","det_state":"...","attack_type":"...",
 *      "window_ms":N,"victim_total_pkts":N,"victim_total_bytes":N}
 *
 * THREAD MODEL
 *   Timer lcore (slow path, once per second):
 *       l3_bridge_set_attack_state()  — update victim attack state
 *       l3_bridge_export_and_reset()  — emit JSON, reset source counters
 *   Forwarding lcores (hot path, once per packet):
 *       l3_bridge_is_under_attack()   — quick check before collecting
 *       l3_bridge_collect_src_packet()— increment per-source counters
 *
 *   All hot-path operations are lock-free (GCC atomic built-ins).
 *   export_and_reset() is called only from one lcore and must not overlap
 *   with another export_and_reset() call.
 *
 * BYTE ORDER
 *   All IP addresses are stored and compared in HOST byte order throughout,
 *   consistent with l2fwd_policy.h.
 *
 * MEMORY
 *   Entirely pre-allocated (no heap allocation in the hot path).
 *   Total worst-case footprint: ~5.5 MB (64 victims × 512 sources × 168 B).
 */

#ifndef __L2FWD_L3_BRIDGE_H__
#define __L2FWD_L3_BRIDGE_H__

#include <stdint.h>
#include <stdbool.h>


/* =========================================================================
 * CONFIGURATION
 * ========================================================================= */

/*
 * UNIX stream socket path — must match config.L3_BRIDGE_SOCKET_PATH in Python.
 * Python (layer3_v1.py start_listener()) creates and listens on this path.
 * C (l3_bridge_export_and_reset()) connects and streams JSON records.
 */
#define L3_BRIDGE_SOCKET_PATH   "/tmp/l3_bridge_socket"

/*
 * Maximum number of simultaneously tracked attack victims.
 * Linear scan at O(n) — keep small (64 is ample for any realistic deployment).
 */
#define L3_BRIDGE_MAX_VICTIMS           64

/*
 * Maximum number of distinct source IPs tracked per victim per window.
 * MUST be a power of two — used as a hash-table mask.
 * 512 sources covers virtually all real DDoS attack source sets within a
 * 1-second window while keeping per-victim memory under 90 KB.
 */
#define L3_BRIDGE_MAX_SOURCES_PER_VICTIM  512


/* =========================================================================
 * PACKET TYPE FLAGS  (passed to l3_bridge_collect_src_packet)
 * ========================================================================= */

#define L3_BRIDGE_PKT_TCP       (1u << 0)   /* packet carries a TCP segment  */
#define L3_BRIDGE_PKT_SYN       (1u << 1)   /* TCP SYN flag set              */
#define L3_BRIDGE_PKT_RST       (1u << 2)   /* TCP RST flag set              */
#define L3_BRIDGE_PKT_ACK_ONLY  (1u << 3)   /* ACK set, no data, no SYN/RST  */


/* =========================================================================
 * PUBLIC API
 * ========================================================================= */

/*
 * l3_bridge_init
 *
 * Zero-fill all internal tables and mark the socket as disconnected.
 * Call once at process startup, before any other l3_bridge_* function.
 */
void l3_bridge_init(void);

/*
 * l3_bridge_set_attack_state
 *
 * Inform the bridge of the current attack state for one victim IP.
 * Called by the Layer 2 detection engine once per 1-second window,
 * on the timer lcore (slow path only — never from a forwarding lcore).
 *
 *   dst_ip      : victim destination IP in HOST byte order
 *   under_attack: true if det_state is SUSPICIOUS or ATTACK
 *   det_state   : NUL-terminated string: "WARMUP"|"NORMAL"|"SUSPICIOUS"|"ATTACK"
 *   attack_type : NUL-terminated string: "SYN_FLOOD"|"UDP_FLOOD"|...|""
 *   window_ms   : epoch milliseconds for this window (used in JSON output)
 *   total_pkts  : total packets seen by L2 for this victim in this window
 *   total_bytes : total bytes seen by L2 for this victim in this window
 *
 * When under_attack transitions from true → false, the victim slot is freed
 * on the next call to l3_bridge_export_and_reset().
 */
void l3_bridge_set_attack_state(uint32_t    dst_ip,
                                bool        under_attack,
                                const char *det_state,
                                const char *attack_type,
                                uint64_t    window_ms,
                                uint64_t    total_pkts,
                                uint64_t    total_bytes);

/*
 * l3_bridge_is_under_attack
 *
 * Returns true if dst_ip currently has an active attack session in the
 * bridge victim table.
 *
 * O(L3_BRIDGE_MAX_VICTIMS) linear scan — all entries fit in a few cache lines.
 * Safe to call concurrently from multiple forwarding lcores (lock-free).
 */
bool l3_bridge_is_under_attack(uint32_t dst_ip);

/*
 * l3_bridge_collect_src_packet
 *
 * Record one packet from src_ip to dst_ip for the current window.
 * Called from the packet forwarding hot path.
 *
 * Does nothing (fast exit) if dst_ip is not currently under attack.
 * Does nothing if the per-victim source table is full (silent drop of
 * tracking for this source — packet is still forwarded normally).
 *
 *   dst_ip    : victim IP in HOST byte order
 *   src_ip    : attacker IP in HOST byte order (must not be 0)
 *   dst_port  : destination TCP/UDP port in HOST byte order (0 for non-TCP/UDP)
 *   src_port  : source TCP/UDP port in HOST byte order (0 for non-TCP/UDP)
 *   pkt_len   : total packet length in bytes
 *   pkt_flags : bitwise-OR of L3_BRIDGE_PKT_* flags
 *
 * Lock-free.  Safe to call concurrently from multiple forwarding lcores.
 */
void l3_bridge_collect_src_packet(uint32_t dst_ip,
                                  uint32_t src_ip,
                                  uint16_t dst_port,
                                  uint16_t src_port,
                                  uint32_t pkt_len,
                                  uint32_t pkt_flags);

/*
 * l3_bridge_export_and_reset
 *
 * For every victim currently tracked:
 *   1. Emit one src_snapshot JSON line per non-empty source slot.
 *   2. Emit one window_end JSON line.
 *   3. Reset all source counters for the next window.
 *   4. If the victim is no longer under attack, free its slot.
 *
 * If the Python listener socket is not connected, one reconnect attempt is
 * made.  If the attempt fails, export is skipped for this tick (tried again
 * next second).
 *
 * Call from the timer lcore once per second, AFTER l3_bridge_set_attack_state()
 * has been called for all victims in this window.
 * NEVER call from a forwarding lcore.
 */
void l3_bridge_export_and_reset(void);


#endif /* __L2FWD_L3_BRIDGE_H__ */
