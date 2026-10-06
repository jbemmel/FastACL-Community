/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */
#include <fastacl/members_only/bloomfilter.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

void
fastacl_bloom_config_default (fastacl_bloom_config_t *config)
{
  *config = (fastacl_bloom_config_t) {
    .expected_subnets = 100000,
    .false_positive_rate = 0.001,
    .validity_seconds = 1800,
    .memory_limit_bytes = FASTACL_BLOOM_DEFAULT_MEMORY,
    .fast_hashing = 1,
  };
}

static int
fastacl_bloom_dimensions_valid (uint32_t bits, uint32_t probes)
{
  return bits >= 64 && bits <= FASTACL_BLOOM_MAX_BITS &&
         (bits & (bits - 1)) == 0 && probes >= 1 &&
         probes <= FASTACL_BLOOM_MAX_PROBES;
}

static double
fastacl_bloom_planned_rate (uint32_t bits, uint32_t probes, uint32_t count)
{
  return pow (-expm1 (-(double) probes * count / bits), probes);
}

const char *
fastacl_bloom_plan (const fastacl_bloom_config_t *config,
                   fastacl_bloom_plan_t *plan)
{
  fastacl_bloom_plan_t p = {
    .banks = config->validity_seconds ? 2 : 1,
    .fast_hashing = config->fast_hashing,
  };
  if (config->fast_hashing > 1)
    return "fast_hashing must be 0 or 1";
  if (!config->expected_subnets || config->expected_subnets > (1U << 24))
    return "expected-subnets must be 1..16777216 (IPv4 /24 identities)";
  if (!isfinite (config->false_positive_rate) ||
      config->false_positive_rate <= 0 || config->false_positive_rate >= 1)
    return "false-positive-rate must be finite and between 0 and 1";
  if (!config->memory_limit_bytes ||
      config->memory_limit_bytes > FASTACL_BLOOM_MAX_MEMORY)
    return "memory limit must be 1..67108864 bytes per zone";
  if (config->validity_seconds == 1 || config->validity_seconds > 31536000)
    return "validity-window must be 0 (no expiry) or 2..31536000 seconds";
  if (config->bits)
    {
      if (!fastacl_bloom_dimensions_valid (config->bits, config->probes))
        return "bits must be a power of two in 64..536870912; probes must be 1..16";
      p.bits = config->bits;
      p.probes = config->probes;
    }
  else
    {
      if (config->probes)
        return "automatic sizing cannot be combined with explicit probes";
      /* Power-of-two storage keeps modulo out of the packet path. Search the
       * bounded probe range at each size and choose the cheapest probe count
       * meeting the target. Budget the OR of the banks using the union bound. */
      for (p.bits = 64;; p.bits <<= 1)
        {
          for (p.probes = 1; p.probes <= FASTACL_BLOOM_MAX_PROBES; p.probes++)
            if (p.banks * fastacl_bloom_planned_rate (
                            p.bits, p.probes, config->expected_subnets) <=
                config->false_positive_rate)
              break;
          if (p.probes <= FASTACL_BLOOM_MAX_PROBES)
            break;
          if (p.bits == FASTACL_BLOOM_MAX_BITS)
            return "target rate cannot be met within the bit/probe limits";
        }
    }
  p.memory_bytes = (uint64_t) p.bits / 8 * p.banks;
  if (p.memory_bytes > config->memory_limit_bytes)
    return "Bloom storage exceeds the zone memory limit";
  p.planned_false_positive_rate = fmin (
    1.0, p.banks * fastacl_bloom_planned_rate (
                    p.bits, p.probes, config->expected_subnets));
  *plan = p;
  return NULL;
}

int
fastacl_bloom_init (fastacl_bloomfilter_t *filter, uint32_t bits,
                   uint32_t probes)
{
  if (filter->words || !fastacl_bloom_dimensions_valid (bits, probes))
    return -1;
  uint64_t *words = calloc (bits / 64, sizeof (*words));
  if (!words)
    return -1;
  *filter = (fastacl_bloomfilter_t) {
    .words = words, .bits = bits, .probes = probes, .fast_hashing = 1,
  };
  return 0;
}

void
fastacl_bloom_destroy (fastacl_bloomfilter_t *filter)
{
  free (filter->words);
  memset (filter, 0, sizeof (*filter));
}

void
fastacl_bloom_clear (fastacl_bloomfilter_t *filter)
{
  if (filter->words)
    memset (filter->words, 0, filter->bits / 8);
}

void
fastacl_bloom_stats (const fastacl_bloomfilter_t *filter,
                    fastacl_bloom_stats_t *stats)
{
  memset (stats, 0, sizeof (*stats));
  if (!filter->words)
    return;
  for (uint32_t i = 0; i < filter->bits / 64; i++)
    stats->set_bits += __builtin_popcountll (
      __atomic_load_n (&filter->words[i], __ATOMIC_RELAXED));
  stats->occupancy = (double) stats->set_bits / filter->bits;
  stats->estimated_subnets = -((double) filter->bits / filter->probes) *
                            log1p (-stats->occupancy);
  stats->estimated_false_positive_rate = pow (stats->occupancy, filter->probes);
}

int
fastacl_bloom_window_init (fastacl_bloom_window_t *window,
                          const fastacl_bloom_plan_t *plan,
                          uint32_t validity_seconds, double now)
{
  if (window->bank[0].words || window->bank[1].words ||
      plan->banks != (validity_seconds ? 2U : 1U) || plan->fast_hashing > 1 ||
      !isfinite (now) ||
      validity_seconds == 1 || validity_seconds > 31536000)
    return -1;
  for (unsigned i = 0; i < plan->banks; i++)
    {
      if (fastacl_bloom_init (&window->bank[i], plan->bits, plan->probes))
        {
          fastacl_bloom_window_destroy (window);
          return -1;
        }
      window->bank[i].fast_hashing = plan->fast_hashing;
    }
  window->active = 0;
  window->rotations = 0;
  window->validity_seconds = validity_seconds;
  window->epoch_start = window->bank_start[0] = now;
  window->bank_start[1] = now - validity_seconds;
  return 0;
}

void
fastacl_bloom_window_destroy (fastacl_bloom_window_t *window)
{
  fastacl_bloom_destroy (&window->bank[0]);
  fastacl_bloom_destroy (&window->bank[1]);
  memset (window, 0, sizeof (*window));
}

void
fastacl_bloom_window_rotate (fastacl_bloom_window_t *window, double now)
{
  double interval = window->validity_seconds / 2.0;
  if (!interval || !isfinite (now) || now < window->epoch_start + interval)
    return;
  double steps = floor ((now - window->epoch_start) / interval);
  /* A delayed process must not preserve approvals beyond the window. */
  if (steps >= 2)
    {
      fastacl_bloom_clear (&window->bank[0]);
      fastacl_bloom_clear (&window->bank[1]);
    }
  if (fmod (steps, 2.0) != 0)
    window->active ^= 1;
  fastacl_bloom_clear (&window->bank[window->active]);
  window->epoch_start += steps * interval;
  window->bank_start[window->active] = window->epoch_start;
  window->bank_start[window->active ^ 1] = window->epoch_start - interval;
  window->rotations += (uint64_t) steps;
}

void
fastacl_bloom_window_learn_ip4 (fastacl_bloom_window_t *window,
                              const uint8_t address[4])
{
  fastacl_bloom_learn_ip4_subnet (&window->bank[window->active], address);
}

int
fastacl_bloom_window_contains_ip4 (const fastacl_bloom_window_t *window,
                                 const uint8_t address[4], double now)
{
  if (!isfinite (now))
    return 0;
  uint64_t hash = window->bank[0].fast_hashing ?
    fastacl_bloom_hash_ip4_subnet_fast (address) :
    fastacl_bloom_hash_ip4_subnet (address);
  for (unsigned i = 0; i < (window->validity_seconds ? 2U : 1U); i++)
    if ((!window->validity_seconds ||
         (now >= window->bank_start[i] &&
          now < window->bank_start[i] + window->validity_seconds)) &&
        fastacl_bloom_contains (&window->bank[i], hash))
      return 1;
  return 0;
}

/* Multiplicative avalanche, with the same result on every architecture.
 * Ordinary unsigned C multiplication needs no optional ISA or runtime dispatch.
 * Unlike seeded CRCs, nonlinear mixing provides distinct double-hash probes. */
static inline uint64_t
fastacl_bloom_mix64 (uint64_t key)
{
  const uint64_t m1 = UINT64_C (0xbf58476d1ce4e5b9);
  const uint64_t m2 = UINT64_C (0x94d049bb133111eb);
  key ^= key >> 30;
  key *= m1;
  key ^= key >> 27;
  key *= m2;
  return key ^ (key >> 31);
}

/* Experimental full-width multiplication followed by high/low XOR folding.
 * The fallback computes the same product halves with portable 32-bit limbs. */
static inline uint64_t
fastacl_bloom_fold64 (uint64_t key)
{
  const uint64_t multiplier = UINT64_C (0xa0761d6478bd642f);
#if defined(__SIZEOF_INT128__)
  __uint128_t product = (__uint128_t) key * multiplier;
  return (uint64_t) product ^ (uint64_t) (product >> 64);
#else
  uint64_t lo_key = (uint32_t) key, hi_key = key >> 32;
  uint64_t lo_mul = (uint32_t) multiplier, hi_mul = multiplier >> 32;
  uint64_t low_product = lo_key * lo_mul;
  uint64_t middle = hi_key * lo_mul + (low_product >> 32);
  uint64_t carry = (uint32_t) middle + lo_key * hi_mul;
  uint64_t high_product = hi_key * hi_mul + (middle >> 32) + (carry >> 32);
  return key * multiplier ^ high_product;
#endif
}

uint64_t
fastacl_bloom_hash24_fast (uint32_t key)
{
  return fastacl_bloom_fold64 ((key & UINT32_C (0x00ffffff)) ^
                              UINT64_C (0x243f6a8885a308d3));
}

uint64_t
fastacl_bloom_hash64_fast (uint64_t key)
{
  return fastacl_bloom_fold64 (key ^ UINT64_C (0x13198a2e03707344));
}

uint64_t
fastacl_bloom_hash24 (uint32_t key)
{
  return fastacl_bloom_mix64 ((key & UINT32_C (0x00ffffff)) ^
                             UINT64_C (0x243f6a8885a308d3));
}

uint64_t
fastacl_bloom_hash64 (uint64_t key)
{
  return fastacl_bloom_mix64 (key ^ UINT64_C (0x13198a2e03707344));
}

static inline uint32_t
fastacl_bloom_ip4_prefix (const uint8_t address[4])
{
  /* Construct a 24-bit prefix explicitly so host byte order cannot change
   * which octet is excluded. Never pass a raw network-order u32 to hash24. */
  uint32_t prefix = ((uint32_t) address[0] << 16) |
                    ((uint32_t) address[1] << 8) | address[2];
  return prefix;
}

uint64_t
fastacl_bloom_hash_ip4_subnet (const uint8_t address[4])
{
  return fastacl_bloom_hash24 (fastacl_bloom_ip4_prefix (address));
}

uint64_t
fastacl_bloom_hash_ip4_subnet_fast (const uint8_t address[4])
{
  return fastacl_bloom_hash24_fast (fastacl_bloom_ip4_prefix (address));
}

static inline uint64_t
fastacl_bloom_filter_hash_ip4 (const fastacl_bloomfilter_t *filter,
                             const uint8_t address[4])
{
  return filter->fast_hashing ? fastacl_bloom_hash_ip4_subnet_fast (address) :
                              fastacl_bloom_hash_ip4_subnet (address);
}

void
fastacl_bloom_learn_ip4_subnet (fastacl_bloomfilter_t *filter,
                              const uint8_t address[4])
{
  fastacl_bloom_insert (filter, fastacl_bloom_filter_hash_ip4 (filter, address));
}

int
fastacl_bloom_contains_ip4_subnet (const fastacl_bloomfilter_t *filter,
                                 const uint8_t address[4])
{
  return fastacl_bloom_contains (filter,
                                fastacl_bloom_filter_hash_ip4 (filter, address));
}

void
fastacl_bloom_insert (fastacl_bloomfilter_t *filter, uint64_t hash)
{
  if (!filter->words)
    return;
  uint32_t bit = (uint32_t) hash;
  uint32_t step = (uint32_t) (hash >> 32) | 1;
  for (unsigned i = 0; i < filter->probes; i++, bit += step)
    {
      uint32_t index = bit & (filter->bits - 1);
      __atomic_fetch_or (&filter->words[index >> 6],
                         UINT64_C (1) << (index & 63), __ATOMIC_RELAXED);
    }
}

int
fastacl_bloom_contains (const fastacl_bloomfilter_t *filter, uint64_t hash)
{
  if (!filter->words)
    return 0;
  uint32_t bit = (uint32_t) hash;
  uint32_t step = (uint32_t) (hash >> 32) | 1;
  for (unsigned i = 0; i < filter->probes; i++, bit += step)
    {
      uint32_t index = bit & (filter->bits - 1);
      if (!(__atomic_load_n (&filter->words[index >> 6], __ATOMIC_RELAXED) &
            (UINT64_C (1) << (index & 63))))
        return 0;
    }
  return 1;
}
