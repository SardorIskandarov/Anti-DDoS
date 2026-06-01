/**
 * @file   tests/load_one.c
 * @brief  Tiny driver: load argv[1] as a services.json, exit with the rc.
 *
 * Used by the cross-validator equivalence test to feed Python and C the
 * EXACT same mutated JSON. The exit code mapping is:
 *   0 → SERVICE_REGISTRY_OK
 *   1 → any non-OK rc (matches the Python validator's failure exit)
 *   2 → bad argv
 */
#include <stdio.h>
#include <stdlib.h>
#include "l2fwd_service_registry.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-services.json>\n", argv[0]);
        return 2;
    }
    static struct service_registry reg;
    int rc = service_registry_load(&reg, argv[1]);
    return (rc == SERVICE_REGISTRY_OK) ? 0 : 1;
}
