/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */
#include <fastacl/members_only/members_only.h>
#include <vnet/ip/ip.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

fastacl_members_only_zone_t *fastacl_members_only_zones;

fastacl_members_only_zone_t *
fastacl_members_only_zone_find (const char *name)
{
  fastacl_members_only_zone_t *zone;
  vec_foreach (zone, fastacl_members_only_zones)
    if (strcmp ((const char *) zone->name, name) == 0)
      return zone;
  return NULL;
}

static int
fastacl_members_only_name_valid (const char *name)
{
  size_t len = strlen (name);
  if (!len || len > 63)
    return 0;
  for (size_t i = 0; i < len; i++)
    if (!isalnum ((unsigned char) name[i]) && name[i] != '-' && name[i] != '_')
      return 0;
  return 1;
}

const char *
fastacl_members_only_zone_configure (vlib_main_t *vm, const char *name,
                                const fastacl_bloom_config_t *config, int reset)
{
  fastacl_bloom_plan_t plan;
  fastacl_members_only_zone_t replacement = { 0 };
  fastacl_members_only_zone_t *zone = fastacl_members_only_zone_find (name);
  if (!fastacl_members_only_name_valid (name))
    return "zone name must be 1..63 letters, digits, '-' or '_'";
  if (zone && !reset)
    return "zone exists: reconfiguration requires reset and discards approvals";
  if (!zone && vec_len (fastacl_members_only_zones) >= FASTACL_MEMBERS_ONLY_MAX_ZONES)
    return "zone count limit (64) exceeded";
  const char *error = fastacl_bloom_plan (config, &plan);
  if (error)
    return error;
  /* Include the old filter while allocating the replacement, limiting peak
   * memory as well as steady-state memory. Failure leaves the old zone intact. */
  uint64_t memory = plan.memory_bytes;
  fastacl_members_only_zone_t *it;
  vec_foreach (it, fastacl_members_only_zones)
    memory += it->plan.memory_bytes;
  if (memory > FASTACL_MEMBERS_ONLY_MAX_TOTAL_MEMORY)
    return "total Bloom memory limit (256 MiB, including replacement) exceeded";
  if (fastacl_bloom_window_init (&replacement.filter, &plan,
                                config->validity_seconds, vlib_time_now (vm)))
    return "cannot allocate Bloom storage";
  replacement.name = format (0, "%s%c", name, 0);
  replacement.config = *config;
  replacement.plan = plan;
  vlib_worker_thread_barrier_sync (vm);
  if (zone)
    {
      fastacl_bloom_window_destroy (&zone->filter);
      vec_free (zone->name);
      *zone = replacement;
    }
  else
    vec_add1 (fastacl_members_only_zones, replacement);
  vlib_worker_thread_barrier_release (vm);
  return NULL;
}

const char *
fastacl_members_only_zone_delete (vlib_main_t *vm, const char *name)
{
  fastacl_members_only_zone_t *zone = fastacl_members_only_zone_find (name);
  if (!zone)
    return "no such members-only zone";
  uword index = zone - fastacl_members_only_zones;
  vlib_worker_thread_barrier_sync (vm);
  fastacl_bloom_window_destroy (&zone->filter);
  vec_free (zone->name);
  vec_delete (fastacl_members_only_zones, 1, index);
  vlib_worker_thread_barrier_release (vm);
  return NULL;
}

static int
fastacl_members_only_rotation_due (double now)
{
  fastacl_members_only_zone_t *zone;
  vec_foreach (zone, fastacl_members_only_zones)
    if (zone->config.validity_seconds &&
        now >= zone->filter.epoch_start + zone->config.validity_seconds / 2.0)
      return 1;
  return 0;
}

static void
fastacl_members_only_rotate (vlib_main_t *vm)
{
  if (!fastacl_members_only_rotation_due (vlib_time_now (vm)))
    return;
  vlib_worker_thread_barrier_sync (vm);
  double now = vlib_time_now (vm);
  fastacl_members_only_zone_t *zone;
  vec_foreach (zone, fastacl_members_only_zones)
    fastacl_bloom_window_rotate (&zone->filter, now);
  vlib_worker_thread_barrier_release (vm);
}

static uword
fastacl_members_only_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
                         vlib_frame_t *frame)
{
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 0.5);
      uword *events = NULL;
      vlib_process_get_events (vm, &events);
      vec_free (events);
      fastacl_members_only_rotate (vm);
    }
  return 0;
}

VLIB_REGISTER_NODE (fastacl_members_only_process_node) = {
  .function = fastacl_members_only_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "fastacl-members-only-expiry",
};

/* Seconds by default, or a single s/m/h/d suffix. Reject overflow and trailing
 * garbage before converting to the public configuration's u32 field. */
static int
fastacl_members_only_duration (const char *text, uint32_t *seconds)
{
  if (!isdigit ((unsigned char) text[0]))
    return 0;
  char *end;
  errno = 0;
  unsigned long long value = strtoull (text, &end, 10);
  if (errno)
    return 0;
  unsigned multiplier = 1;
  if (*end)
    {
      if (end[1])
        return 0;
      switch (*end)
        {
        case 's': break;
        case 'm': multiplier = 60; break;
        case 'h': multiplier = 3600; break;
        case 'd': multiplier = 86400; break;
        default: return 0;
        }
    }
  if (value > UINT32_MAX / multiplier)
    return 0;
  *seconds = value * multiplier;
  return 1;
}

static clib_error_t *
fastacl_members_only_zone_cli (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  fastacl_bloom_config_t config;
  fastacl_bloom_config_default (&config);
  u8 *name = NULL, *duration = NULL;
  clib_error_t *error = NULL;
  unsigned seen = 0;
  int reset = 0;
  if (!unformat (input, "%s", &name))
    return clib_error_return (0, "a zone name is required");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unsigned option = 0;
      u32 mb, bits_log2;
      if (unformat (input, "bloom expected-subnets %u", &config.expected_subnets))
        option = 1;
      else if (unformat (input, "false-positive-rate %f",
                         &config.false_positive_rate))
        option = 2;
      else if (unformat (input, "bloom bits %u", &bits_log2))
        {
          option = 4;
          if (bits_log2 < 6 || bits_log2 > 29)
            {
              error = clib_error_return (0, "bloom bits log2 must be in 6..29");
              goto done;
            }
          config.bits = UINT32_C (1) << bits_log2;
        }
      else if (unformat (input, "probes %u", &config.probes))
        option = 8;
      else if (unformat (input, "validity-window %s", &duration))
        {
          option = 16;
          if (!fastacl_members_only_duration ((const char *) duration,
                                         &config.validity_seconds))
            {
              error = clib_error_return (0, "invalid validity-window duration");
              goto done;
            }
          vec_free (duration);
        }
      else if (unformat (input, "memory-limit-mb %u", &mb))
        {
          option = 32;
          config.memory_limit_bytes = (uint64_t) mb << 20;
        }
      else if (unformat (input, "fast_hashing %u", &config.fast_hashing))
        option = 128;
      else if (unformat (input, "reset"))
        {
          option = 64;
          reset = 1;
        }
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, input);
          goto done;
        }
      if (seen & option)
        {
          error = clib_error_return (0, "duplicate configuration option");
          goto done;
        }
      seen |= option;
    }
  if ((seen & 12) && ((seen & 12) != 12 || !config.bits || !config.probes ||
                     (seen & 2)))
    {
      error = clib_error_return (
        0, "explicit sizing requires bloom bits and probes; omit false-positive-rate");
      goto done;
    }
  const char *message = fastacl_members_only_zone_configure (
    vm, (const char *) name, &config, reset);
  if (message)
    error = clib_error_return (0, "%s", message);
  else
    vlib_cli_output (vm, "Zone %s configured; client prefix IPv4 /24%s", name,
                     reset ? "; learned approvals reset" : "");
done:
  vec_free (name);
  vec_free (duration);
  return error;
}

VLIB_CLI_COMMAND (fastacl_members_only_zone_command, static) = {
  .path = "fastacl members-only zone",
  .short_help = "fastacl members-only zone <name> "
    "[bloom expected-subnets <n> false-positive-rate <p> | bloom bits <log2:6..29> probes <k>] "
    "[validity-window <seconds|30m|1h|0>] [memory-limit-mb <1..64>] [fast_hashing <0|1>] [reset]",
  .function = fastacl_members_only_zone_cli,
};

static clib_error_t *
fastacl_members_only_delete_cli (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  u8 *name = NULL;
  if (!unformat (input, "%s", &name))
    return clib_error_return (0, "a zone name is required");
  const char *message = unformat_check_input (input) != UNFORMAT_END_OF_INPUT ?
    "unexpected input after zone name" :
    fastacl_members_only_zone_delete (vm, (const char *) name);
  vec_free (name);
  return message ? clib_error_return (0, "%s", message) : NULL;
}

VLIB_CLI_COMMAND (fastacl_members_only_delete_command, static) = {
  .path = "fastacl members-only delete",
  .short_help = "fastacl members-only delete <name>",
  .function = fastacl_members_only_delete_cli,
};

static clib_error_t *
fastacl_members_only_show_cli (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  u8 *name = NULL;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT &&
      !unformat (input, "%s", &name))
    return clib_error_return (0, "expected a zone name");
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (name);
      return clib_error_return (0, "unexpected input after zone name");
    }
  if (name && !fastacl_members_only_zone_find ((const char *) name))
    {
      vec_free (name);
      return clib_error_return (0, "no such members-only zone");
    }
  fastacl_members_only_rotate (vm);
  uint64_t total_memory = 0;
  fastacl_members_only_zone_t *zone;
  vec_foreach (zone, fastacl_members_only_zones)
    {
      total_memory += zone->plan.memory_bytes;
      if (name && strcmp ((const char *) zone->name, (const char *) name))
        continue;
      vlib_cli_output (vm, "Zone %s: IPv4 /24, %s sizing", zone->name,
                       zone->config.bits ? "explicit" : "automatic");
      vlib_cli_output (vm, "  bits/bank %u probes %u banks %u memory %llu bytes (limit %llu)",
                       zone->plan.bits, zone->plan.probes, zone->plan.banks,
                       (unsigned long long) zone->plan.memory_bytes,
                       (unsigned long long) zone->config.memory_limit_bytes);
      vlib_cli_output (vm, "  fast_hashing %u (%s)", zone->config.fast_hashing,
                       zone->config.fast_hashing ? "experimental multiply/fold" :
                                                   "original C mixer");
      vlib_cli_output (vm, "  expected-subnets %u planned-fpr %.6g",
                       zone->config.expected_subnets,
                       zone->plan.planned_false_positive_rate);
      if (!zone->config.bits)
        vlib_cli_output (vm, "  target-fpr %.6g",
                         zone->config.false_positive_rate);
      vlib_cli_output (vm, "  validity-window %u seconds rotations %llu active-bank %u",
                       zone->config.validity_seconds,
                       (unsigned long long) zone->filter.rotations, zone->filter.active);
      double rate = 0;
      for (unsigned i = 0; i < zone->plan.banks; i++)
        {
          fastacl_bloom_stats_t stats;
          fastacl_bloom_stats (&zone->filter.bank[i], &stats);
          rate += stats.estimated_false_positive_rate;
          u8 *count = isfinite (stats.estimated_subnets) ?
            format (0, "%.0f%c", stats.estimated_subnets, 0) :
            format (0, "saturated%c", 0);
          vlib_cli_output (vm, "  bank %u occupancy %.2f%% "
                           "estimated-subnets %s estimated-fpr %.6g%s",
                           i, stats.occupancy * 100, count,
                           stats.estimated_false_positive_rate,
                           stats.estimated_subnets > zone->config.expected_subnets ?
                             " capacity-exceeded" : "");
          vec_free (count);
        }
      rate = fmin (1.0, rate);
      vlib_cli_output (vm, "  combined estimated-fpr bound %.6g%s", rate,
                       !zone->config.bits && rate > zone->config.false_positive_rate ?
                         " target-exceeded" : "");
    }
  vlib_cli_output (vm, "Bloom memory: %llu / %llu bytes across %u zones",
                   (unsigned long long) total_memory,
                   (unsigned long long) FASTACL_MEMBERS_ONLY_MAX_TOTAL_MEMORY,
                   vec_len (fastacl_members_only_zones));
  vec_free (name);
  return NULL;
}

VLIB_CLI_COMMAND (fastacl_members_only_show_command, static) = {
  .path = "show fastacl members-only",
  .short_help = "show fastacl members-only [name]",
  .function = fastacl_members_only_show_cli,
};
