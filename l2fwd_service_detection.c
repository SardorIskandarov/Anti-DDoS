/**
 * @file   l2fwd_service_detection.c
 * @brief  Per-service detection state lifecycle — P5 implementation.
 *
 * Pure storage + lifecycle. No CUSUM math, no EWMA, no phase transitions.
 * Hot-path packet code does not call any of these functions yet — P9 wires
 * them up.
 */

#include "l2fwd_service_detection.h"
#include "l2fwd_l2_profile.h"   /* full struct l2_profile for warmup_windows */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

struct service_detection_state *service_detection_state_alloc(void) {
    struct service_detection_state *det =
        calloc(1, sizeof(struct service_detection_state));
    if (!det) {
        fprintf(stderr,
                "[service_detection] [ERROR] alloc of %zu bytes failed\n",
                sizeof(struct service_detection_state));
        return NULL;
    }
    return det;
}

int service_detection_state_init(struct service_detection_state *det,
                                  const struct l2_profile *profile)
{
    if (!det) return -1;

    /* Idempotent re-init: clear everything then set fields. */
    memset(det, 0, sizeof(*det));

    det->profile    = profile;
    det->phase      = (uint8_t)SERVICE_DET_PHASE_WARMUP;
    det->prev_phase = (uint8_t)SERVICE_DET_PHASE_WARMUP;
    det->active     = true;

    /* Warmup: prefer the profile-supplied value; fall back to the macro
     * matching the legacy DETECTION_WARMUP_WINDOWS = 400. */
    if (profile && profile->warmup_windows > 0) {
        det->warmup_remaining = profile->warmup_windows;
    } else {
        det->warmup_remaining = SERVICE_DETECTION_DEFAULT_WARMUP_WINDOWS;
    }
    det->warmup_windows_completed = 0;

    /* CUSUM + last_* fields already zeroed by memset above. */
    return 0;
}

void service_detection_state_reset_window(struct service_detection_state *det)
{
    if (!det) return;

    /* PRESERVE: phase, prev_phase, CUSUM accumulators, warmup_remaining,
     * warmup_windows_completed, consecutive_attack_windows, freeze/thaw
     * counters, profile, last_phase_change_window. */

    /* Zero just the last_* cached scores. */
    det->last_tier0_score          = 0.0;
    det->last_tier0_risk_pps       = 0.0;
    det->last_tier0_risk_bps       = 0.0;
    det->last_tier0_risk_fps       = 0.0;
    det->last_tier0_risk_burst_pps = 0.0;
    det->last_tier0_risk_burst_bps = 0.0;
    det->last_tier0_risk_burst_fps = 0.0;
    det->last_tier1_tcp_score      = 0.0;
    det->last_tier1_udp_score      = 0.0;
    det->last_tier1_icmp_score     = 0.0;
    det->last_tier1_dist_score     = 0.0;
    det->last_tier1_l3_score       = 0.0;
    det->last_tier1_offproto_score = 0.0;
    det->last_tier1_final_score    = 0.0;
    det->last_tier1_evaluated      = false;
    det->last_attack_evidence      = 0.0;

    det->windows_seen++;
}

void service_detection_state_destroy(struct service_detection_state *det) {
    if (!det) return;
    free(det);
}

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */

const char *service_detection_phase_name(uint8_t phase) {
    switch (phase) {
    case SERVICE_DET_PHASE_WARMUP:     return "WARMUP";
    case SERVICE_DET_PHASE_NORMAL:     return "NORMAL";
    case SERVICE_DET_PHASE_SUSPICIOUS: return "SUSPICIOUS";
    case SERVICE_DET_PHASE_ATTACK:     return "ATTACK";
    default:                           return "UNKNOWN";
    }
}

void service_detection_state_log(const struct service_detection_state *det) {
    if (!det) {
        fprintf(stderr, "[service_detection] (NULL)\n");
        return;
    }
    fprintf(stderr,
            "[service_detection] phase=%s warmup_rem=%u consecutive_attack=%u "
            "freeze_rem=%u thaw_rem=%u last_tier1_final=%.3f windows_seen=%llu\n",
            service_detection_phase_name(det->phase),
            (unsigned)det->warmup_remaining,
            (unsigned)det->consecutive_attack_windows,
            (unsigned)det->baseline_freeze_remaining,
            (unsigned)det->thaw_cooldown_remaining,
            det->last_tier1_final_score,
            (unsigned long long)det->windows_seen);
}
