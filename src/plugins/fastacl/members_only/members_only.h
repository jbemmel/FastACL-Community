/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */
#ifndef included_fastacl_members_only_h
#define included_fastacl_members_only_h

#include <vlib/vlib.h>
#include <fastacl/members_only/bloomfilter.h>

#define FASTACL_MEMBERS_ONLY_MAX_ZONES 64
#define FASTACL_MEMBERS_ONLY_MAX_TOTAL_MEMORY (UINT64_C (256) << 20)

typedef struct
{
  u8 *name;
  fastacl_bloom_config_t config;
  fastacl_bloom_plan_t plan;
  fastacl_bloom_window_t filter;
} fastacl_members_only_zone_t;

extern fastacl_members_only_zone_t *fastacl_members_only_zones;
/* Global maintenance cadence in seconds, configured at startup. */
extern f64 fastacl_members_only_check_interval;

/* Call these control-plane operations on the main thread. They synchronize
 * publication, reclamation and clearing with packet workers internally. */
fastacl_members_only_zone_t *fastacl_members_only_zone_find (const char *name);
const char *fastacl_members_only_zone_configure (
  vlib_main_t *vm, const char *name, const fastacl_bloom_config_t *config,
  int reset);
const char *fastacl_members_only_zone_delete (vlib_main_t *vm, const char *name);

/* Future packet actions must resolve their zone under worker synchronization.
 * Do not retain pointers across control-plane updates: the zone vector moves.
 * IPv4 /24 learning/checking uses zone->filter via bloomfilter.h. */

#endif
