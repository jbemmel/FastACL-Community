/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <fastacl/members_only/bloomfilter.h>

static void
test_plans (void)
{
  fastacl_bloom_config_t config;
  fastacl_bloom_plan_t plan;
  fastacl_bloom_config_default (&config);
  assert (!fastacl_bloom_plan (&config, &plan));
  assert (config.fast_hashing == 1 && plan.fast_hashing == 1);
  config.fast_hashing = 0;
  assert (!fastacl_bloom_plan (&config, &plan) && !plan.fast_hashing);
  config.fast_hashing = 2;
  assert (fastacl_bloom_plan (&config, &plan));
  config.fast_hashing = 1;
  assert (!fastacl_bloom_plan (&config, &plan));
  assert (plan.banks == 2);
  assert (plan.bits == (1U << 21));
  assert (plan.probes >= 1 && plan.probes <= FASTACL_BLOOM_MAX_PROBES);
  assert (plan.memory_bytes == (uint64_t) plan.bits / 8 * 2);
  assert (plan.planned_false_positive_rate <= config.false_positive_rate);
  /* Every lower probe count at the selected allocation fails the target. */
  for (unsigned k = 1; k < plan.probes; k++)
    assert (2 * pow (-expm1 (-(double) k * config.expected_subnets / plan.bits), k)
            > config.false_positive_rate);
  config.validity_seconds = 0;
  assert (!fastacl_bloom_plan (&config, &plan) && plan.banks == 1);
  assert (plan.memory_bytes == plan.bits / 8);

  config.bits = FASTACL_BLOOM_BITS;
  config.probes = FASTACL_BLOOM_PROBES;
  assert (!fastacl_bloom_plan (&config, &plan));
  assert (plan.bits == config.bits && plan.probes == config.probes);
  config.bits++;
  assert (fastacl_bloom_plan (&config, &plan));
  config.bits = 32;
  assert (fastacl_bloom_plan (&config, &plan));
  config.bits = FASTACL_BLOOM_BITS;
  config.probes = FASTACL_BLOOM_MAX_PROBES + 1;
  assert (fastacl_bloom_plan (&config, &plan));
  config.probes = 0;
  assert (fastacl_bloom_plan (&config, &plan));
  config.bits = 0;
  config.probes = 4;
  assert (fastacl_bloom_plan (&config, &plan));

  fastacl_bloom_config_default (&config);
  config.memory_limit_bytes = 1;
  assert (fastacl_bloom_plan (&config, &plan));
  config.memory_limit_bytes = FASTACL_BLOOM_MAX_MEMORY + 1;
  assert (fastacl_bloom_plan (&config, &plan));
  fastacl_bloom_config_default (&config);
  config.expected_subnets = 0;
  assert (fastacl_bloom_plan (&config, &plan));
  config.expected_subnets = (1U << 24) + 1;
  assert (fastacl_bloom_plan (&config, &plan));
  fastacl_bloom_config_default (&config);
  double invalid[] = { 0, -0.1, 1, NAN, INFINITY };
  for (unsigned i = 0; i < sizeof (invalid) / sizeof (invalid[0]); i++)
    {
      config.false_positive_rate = invalid[i];
      assert (fastacl_bloom_plan (&config, &plan));
    }
  fastacl_bloom_config_default (&config);
  config.validity_seconds = 1;
  assert (fastacl_bloom_plan (&config, &plan));
  config.validity_seconds = UINT32_MAX;
  assert (fastacl_bloom_plan (&config, &plan));
  fastacl_bloom_config_default (&config);
  config.expected_subnets = 1U << 24;
  config.false_positive_rate = 1e-100;
  assert (fastacl_bloom_plan (&config, &plan));
}

static void
test_dimensions_and_stats (void)
{
  fastacl_bloomfilter_t filter = { 0 };
  fastacl_bloom_stats_t stats;
  assert (!fastacl_bloom_contains (&filter, 42));
  assert (fastacl_bloom_init (&filter, 65, 1));
  assert (fastacl_bloom_init (&filter, 64, 0));
  for (unsigned k = 1; k <= FASTACL_BLOOM_MAX_PROBES; k++)
    {
      assert (!fastacl_bloom_init (&filter, 1024, k));
      assert (fastacl_bloom_init (&filter, 1024, k)); /* no leaking replacement */
      fastacl_bloom_stats (&filter, &stats);
      assert (stats.set_bits == 0 && stats.estimated_subnets == 0);
      uint64_t hash = fastacl_bloom_hash64 (42);
      fastacl_bloom_insert (&filter, hash);
      assert (fastacl_bloom_contains (&filter, hash));
      fastacl_bloom_stats (&filter, &stats);
      assert (stats.set_bits == k);
      assert (stats.occupancy == k / 1024.0);
      /* Refreshing an identity does not increase occupancy or cardinality. */
      fastacl_bloom_insert (&filter, hash);
      fastacl_bloom_stats_t after;
      fastacl_bloom_stats (&filter, &after);
      assert (after.set_bits == stats.set_bits);
      fastacl_bloom_clear (&filter);
      assert (!fastacl_bloom_contains (&filter, hash));
      memset (filter.words, 0xff, filter.bits / 8);
      fastacl_bloom_stats (&filter, &stats);
      assert (stats.occupancy == 1 && stats.estimated_false_positive_rate == 1);
      assert (isinf (stats.estimated_subnets));
      fastacl_bloom_destroy (&filter);
      assert (!filter.words && !filter.bits && !filter.probes);
    }
}

static void
test_rotation (uint32_t fast_hashing)
{
  const uint8_t early[4] = { 198, 51, 100, 1 };
  const uint8_t late[4] = { 198, 51, 101, 2 };
  fastacl_bloom_config_t config;
  fastacl_bloom_plan_t plan;
  fastacl_bloom_window_t window = { 0 };
  fastacl_bloom_config_default (&config);
  config.bits = 1U << 16;
  config.probes = 4;
  config.validity_seconds = 10;
  config.fast_hashing = fast_hashing;
  assert (!fastacl_bloom_plan (&config, &plan));
  assert (!fastacl_bloom_window_init (&window, &plan, 10, 100));
  assert (window.bank[0].fast_hashing == fast_hashing &&
          window.bank[1].fast_hashing == fast_hashing);
  assert (fastacl_bloom_window_init (&window, &plan, 10, 100));
  fastacl_bloom_window_learn_ip4 (&window, early);
  assert (fastacl_bloom_window_contains_ip4 (&window, early, 104.99));
  assert (!fastacl_bloom_window_contains_ip4 (&window, early, NAN));
  fastacl_bloom_window_rotate (&window, 104.99);
  assert (window.rotations == 0);
  fastacl_bloom_window_rotate (&window, 105);
  assert (window.rotations == 1 && window.active == 1);
  assert (fastacl_bloom_window_contains_ip4 (&window, early, 105));
  fastacl_bloom_window_learn_ip4 (&window, late);
  /* The clock check expires old banks even if the rotation process is late. */
  assert (!fastacl_bloom_window_contains_ip4 (&window, early, 110));
  assert (fastacl_bloom_window_contains_ip4 (&window, late, 110));
  fastacl_bloom_window_rotate (&window, 110);
  assert (!fastacl_bloom_window_contains_ip4 (&window, early, 110));
  assert (fastacl_bloom_window_contains_ip4 (&window, late, 110));
  fastacl_bloom_window_learn_ip4 (&window, late); /* refresh */
  fastacl_bloom_window_rotate (&window, 115);
  assert (fastacl_bloom_window_contains_ip4 (&window, late, 115));
  fastacl_bloom_window_rotate (&window, 140); /* catch up five epochs */
  assert (window.rotations == 8 && window.epoch_start == 140);
  assert (!fastacl_bloom_window_contains_ip4 (&window, late, 140));
  fastacl_bloom_window_learn_ip4 (&window, early);
  fastacl_bloom_window_rotate (&window, 139); /* backwards clock does not clear */
  assert (fastacl_bloom_window_contains_ip4 (&window, early, 140));
  fastacl_bloom_window_destroy (&window);

  config.validity_seconds = 0;
  assert (!fastacl_bloom_plan (&config, &plan));
  assert (!fastacl_bloom_window_init (&window, &plan, 0, 0));
  assert (!window.bank[1].words);
  fastacl_bloom_window_learn_ip4 (&window, late);
  fastacl_bloom_window_rotate (&window, 1e8);
  assert (window.rotations == 0);
  assert (fastacl_bloom_window_contains_ip4 (&window, late, 1e8));
  fastacl_bloom_window_destroy (&window);
}

static void
test_hash_modes (void)
{
  fastacl_bloom_config_t config;
  fastacl_bloom_plan_t plan;
  fastacl_bloom_config_default (&config);
  config.bits = 1U << 21;
  config.probes = 4;
  config.validity_seconds = 0;
  for (uint32_t mode = 0; mode <= 1; mode++)
    {
      config.fast_hashing = mode;
      assert (!fastacl_bloom_plan (&config, &plan));
      fastacl_bloom_window_t window = { 0 };
      fastacl_bloomfilter_t expected = { 0 };
      assert (!fastacl_bloom_window_init (&window, &plan, 0, 0));
      assert (!fastacl_bloom_init (&expected, plan.bits, plan.probes));
      assert (expected.fast_hashing == 1);
      for (uint32_t prefix = 0; prefix < 100000; prefix++)
        {
          uint8_t ip[4] = { prefix >> 16, prefix >> 8, prefix, 42 };
          fastacl_bloom_window_learn_ip4 (&window, ip);
          uint64_t hash = mode ? fastacl_bloom_hash24_fast (prefix) :
                                 fastacl_bloom_hash24 (prefix);
          fastacl_bloom_insert (&expected, hash);
        }
      /* Prove the configuration selects the specified hash during learning. */
      assert (!memcmp (expected.words, window.bank[0].words, plan.bits / 8));
      unsigned false_positives = 0;
      for (uint32_t prefix = 0; prefix < 1100000; prefix++)
        {
          uint8_t ip[4] = { prefix >> 16, prefix >> 8, prefix, 99 };
          int found = fastacl_bloom_window_contains_ip4 (&window, ip, 1);
          if (prefix < 100000)
            assert (found); /* All hosts in the learned /24 remain approved. */
          else
            false_positives += found;
        }
      assert (false_positives < 2000);
      printf ("Hash mode %u: %u/1000000 false positives\n", mode, false_positives);
      fastacl_bloom_window_destroy (&window);
      fastacl_bloom_destroy (&expected);
    }
  plan.fast_hashing = 2;
  fastacl_bloom_window_t invalid = { 0 };
  assert (fastacl_bloom_window_init (&invalid, &plan, 0, 0));
  assert (!invalid.bank[0].words);
}

int
main (void)
{
  test_plans ();
  test_dimensions_and_stats ();
  test_hash_modes ();
  test_rotation (0);
  test_rotation (1);
  puts ("Bloom sizing, validation, occupancy and expiry tests passed");
  return 0;
}
