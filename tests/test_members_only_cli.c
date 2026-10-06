/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

/* Exercise the real CLI parser and zone lifecycle with VPP's format/heap
 * library. Only worker barriers and CLI output are replaced by test hooks;
 * this harness does not start a VPP packet-processing runtime. */
#include <fastacl/members_only/members_only.c>

static int barrier_depth;
static unsigned barrier_count;
static u8 *output;

void
vlib_worker_thread_barrier_sync_int (vlib_main_t *vm, const char *function)
{
  assert (!barrier_depth);
  barrier_depth++;
  barrier_count++;
}

void
vlib_worker_thread_barrier_release (vlib_main_t *vm)
{
  assert (barrier_depth == 1);
  barrier_depth--;
}

void
vlib_cli_output (vlib_main_t *vm, char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  output = va_format (output, fmt, &args);
  output = format (output, "\n");
  va_end (args);
}

static void
run_cli (vlib_main_t *vm, vlib_cli_command_t *command, const char *text,
         int expect_error)
{
  unformat_input_t input;
  unformat_init_string (&input, text, strlen (text));
  clib_error_t *error = command->function (vm, &input, command);
  assert (!!error == expect_error);
  clib_error_free (error);
  unformat_free (&input);
  assert (!barrier_depth);
}

int
main (void)
{
  clib_mem_init (NULL, 64 << 20);
  vlib_main_t vm;
  memset (&vm, 0, sizeof (vm));
  clib_time_init (&vm.clib_time);
  run_cli (&vm, &fastacl_members_only_zone_command,
           "website bloom expected-subnets 100000 false-positive-rate 0.001 validity-window 30m",
           0);
  fastacl_members_only_zone_t *zone = fastacl_members_only_zone_find ("website");
  assert (zone && zone->config.validity_seconds == 1800);
  assert (zone->config.fast_hashing == 1 && zone->plan.fast_hashing == 1);
  assert (zone->filter.bank[0].fast_hashing == 1 &&
          zone->filter.bank[1].fast_hashing == 1);
  assert (zone->plan.memory_bytes == (1U << 19));
  assert (barrier_count == 1);
  run_cli (&vm, &fastacl_members_only_show_command, "website", 0);
  output = format (output, "%c", 0);
  assert (strstr ((char *) output, "fast_hashing 1 (experimental multiply/fold)"));
  vec_free (output);
  const u8 ip[4] = { 198, 51, 100, 42 };
  fastacl_bloom_window_learn_ip4 (&zone->filter, ip);
  assert (fastacl_bloom_window_contains_ip4 (&zone->filter, ip, vlib_time_now (&vm)));

  run_cli (&vm, &fastacl_members_only_zone_command, "website bloom bits 10 probes 2 fast_hashing 0", 1);
  assert (fastacl_bloom_window_contains_ip4 (&zone->filter, ip, vlib_time_now (&vm)));
  const char *bad[] = {
    "bad bloom bits 1000 probes 2",
    "bad bloom bits 5 probes 2",
    "bad bloom bits 30 probes 2",
    "bad bloom bits 32 probes 2",
    "bad bloom bits 1048576 probes 2",
    "bad bloom bits 10 probes 17",
    "bad bloom bits 10 probes 0",
    "bad bloom bits 10",
    "bad bloom bits 0 probes 2",
    "bad probes 2",
    "bad bloom bits 10 probes 2 false-positive-rate 0.01",
    "bad bloom expected-subnets 0",
    "bad bloom expected-subnets 16777217",
    "bad bloom expected-subnets 100000 false-positive-rate 0",
    "bad bloom expected-subnets 100000 false-positive-rate 1",
    "bad validity-window 1",
    "bad validity-window 30mx",
    "bad validity-window -1",
    "bad validity-window 99999999999999999999999999",
    "bad memory-limit-mb 0",
    "bad memory-limit-mb 65",
    "bad bloom bits 24 probes 2 memory-limit-mb 1",
    "bad reset reset",
    "bad validity-window 10m validity-window 20m",
    "bad fast_hashing 2",
    "bad fast_hashing -1",
    "bad fast_hashing",
    "bad fast_hashing 0 fast_hashing 1",
    "bad typo",
    "bad/name",
  };
  for (unsigned i = 0; i < ARRAY_LEN (bad); i++)
    {
      run_cli (&vm, &fastacl_members_only_zone_command, bad[i], 1);
      assert (!fastacl_members_only_zone_find ("bad"));
      assert (vec_len (fastacl_members_only_zones) == 1);
    }
  run_cli (&vm, &fastacl_members_only_zone_command,
           "website bloom bits 20 probes 4 validity-window 0 fast_hashing 0 reset", 0);
  zone = fastacl_members_only_zone_find ("website");
  assert (zone->plan.banks == 1 && zone->config.bits == 1048576);
  assert (!zone->config.fast_hashing && !zone->filter.bank[0].fast_hashing);
  assert (!fastacl_bloom_window_contains_ip4 (&zone->filter, ip, vlib_time_now (&vm)));
  fastacl_bloom_window_learn_ip4 (&zone->filter, ip);
  assert (fastacl_bloom_window_contains_ip4 (&zone->filter, ip, vlib_time_now (&vm)));
  fastacl_bloom_clear (&zone->filter.bank[0]);
  run_cli (&vm, &fastacl_members_only_show_command, "website", 0);
  output = format (output, "%c", 0);
  assert (strstr ((char *) output, "explicit sizing"));
  assert (strstr ((char *) output, "fast_hashing 0 (original C mixer)"));
  assert (strstr ((char *) output, "occupancy 0.00%"));
  memset (zone->filter.bank[0].words, 0xff, zone->plan.bits / 8);
  vec_free (output);
  run_cli (&vm, &fastacl_members_only_show_command, "website", 0);
  output = format (output, "%c", 0);
  assert (strstr ((char *) output, "estimated-subnets saturated"));
  run_cli (&vm, &fastacl_members_only_show_command, "missing", 1);
  run_cli (&vm, &fastacl_members_only_delete_command, "website junk", 1);
  run_cli (&vm, &fastacl_members_only_delete_command, "website", 0);
  assert (!fastacl_members_only_zone_find ("website"));
  run_cli (&vm, &fastacl_members_only_delete_command, "website", 1);
  run_cli (&vm, &fastacl_members_only_zone_command,
           "boundary bloom bits 6 probes 1 validity-window 0", 0);
  zone = fastacl_members_only_zone_find ("boundary");
  assert (zone && zone->config.bits == 64 && zone->plan.bits == 64);
  run_cli (&vm, &fastacl_members_only_delete_command, "boundary", 0);
  run_cli (&vm, &fastacl_members_only_zone_command,
           "boundary bloom bits 29 probes 1 validity-window 0 memory-limit-mb 64", 0);
  zone = fastacl_members_only_zone_find ("boundary");
  assert (zone && zone->config.bits == (1U << 29));
  run_cli (&vm, &fastacl_members_only_delete_command, "boundary", 0);
  fastacl_bloom_config_t config;
  fastacl_bloom_config_default (&config);
  config.bits = 1U << 28;
  config.probes = 1;
  config.validity_seconds = 0;
  config.memory_limit_bytes = FASTACL_BLOOM_MAX_MEMORY;
  char name[32];
  for (unsigned i = 0; i < 8; i++)
    {
      snprintf (name, sizeof (name), "memory%u", i);
      assert (!fastacl_members_only_zone_configure (&vm, name, &config, 0));
    }
  assert (fastacl_members_only_zone_configure (&vm, "overflow", &config, 0));
  /* Replacement memory counts toward the peak, and failure preserves a zone. */
  assert (fastacl_members_only_zone_configure (&vm, "memory0", &config, 1));
  assert (fastacl_members_only_zone_find ("memory0"));
  for (unsigned i = 0; i < 8; i++)
    {
      snprintf (name, sizeof (name), "memory%u", i);
      assert (!fastacl_members_only_zone_delete (&vm, name));
    }
  config.bits = 64;
  config.expected_subnets = 1;
  for (unsigned i = 0; i < FASTACL_MEMBERS_ONLY_MAX_ZONES; i++)
    {
      snprintf (name, sizeof (name), "count%u", i);
      assert (!fastacl_members_only_zone_configure (&vm, name, &config, 0));
    }
  assert (fastacl_members_only_zone_configure (&vm, "overflow", &config, 0));
  for (unsigned i = 0; i < FASTACL_MEMBERS_ONLY_MAX_ZONES; i++)
    {
      snprintf (name, sizeof (name), "count%u", i);
      assert (!fastacl_members_only_zone_delete (&vm, name));
    }
  vec_free (fastacl_members_only_zones);
  vec_free (output);
  puts ("Members-only CLI parsing, reset and lifecycle tests passed");
  return 0;
}
