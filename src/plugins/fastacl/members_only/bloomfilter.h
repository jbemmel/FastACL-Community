/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */
#ifndef included_fastacl_bloomfilter_h
#define included_fastacl_bloomfilter_h

#include <stdint.h>

/* Legacy defaults; callers now explicitly initialize dynamically sized storage.
 * Zero-initialize filter/window structs before calling init.
 * Concurrent insertion and lookup are supported. Initialize, clear, destroy,
 * reconfigure and rotate only while readers and writers are stopped.
 * A positive lookup is probabilistic, not proof of authentication. */
#define FASTACL_BLOOM_BITS (1U << 20)
#define FASTACL_BLOOM_PROBES 4
#define FASTACL_BLOOM_MAX_BITS (1U << 29)
#define FASTACL_BLOOM_MAX_PROBES 16
#define FASTACL_BLOOM_DEFAULT_MEMORY (UINT64_C (16) << 20)
#define FASTACL_BLOOM_MAX_MEMORY (UINT64_C (64) << 20)

typedef struct
{
  uint32_t expected_subnets;
  double false_positive_rate;
  /* bits=0 selects automatic sizing; explicit bits require probes=1..16. */
  uint32_t bits;
  uint32_t probes;
  /* 0 disables expiry; otherwise two banks rotate every window/2 seconds. */
  uint32_t validity_seconds;
  uint64_t memory_limit_bytes;
  /* 1 selects experimental multiply/fold; 0 selects the original mixer. */
  uint32_t fast_hashing;
} fastacl_bloom_config_t;

typedef struct
{
  uint32_t bits; /* power of two, per bank */
  uint32_t probes;
  uint32_t banks;
  uint32_t fast_hashing;
  uint64_t memory_bytes;
  double planned_false_positive_rate; /* conservative sum across banks */
} fastacl_bloom_plan_t;

typedef struct
{
  uint64_t *words;
  uint32_t bits;
  uint32_t probes;
  /* Fixed at initialization; changing it requires clearing stored hashes. */
  uint32_t fast_hashing;
} fastacl_bloomfilter_t;

typedef struct
{
  fastacl_bloomfilter_t bank[2];
  double bank_start[2];
  double epoch_start;
  uint32_t validity_seconds;
  uint32_t active;
  uint64_t rotations;
} fastacl_bloom_window_t;

typedef struct
{
  uint64_t set_bits;
  double occupancy;
  double estimated_subnets;
  double estimated_false_positive_rate;
} fastacl_bloom_stats_t;

void fastacl_bloom_config_default (fastacl_bloom_config_t *config);
/* Return NULL on success, or a static error message. No allocations. */
const char *fastacl_bloom_plan (const fastacl_bloom_config_t *config,
                              fastacl_bloom_plan_t *plan);
/* Direct filter initialization defaults to fast hashing. Window initialization
 * uses the mode in its plan. Raw insert/contains accept caller-supplied hashes. */
int fastacl_bloom_init (fastacl_bloomfilter_t *filter, uint32_t bits,
                       uint32_t probes);
void fastacl_bloom_destroy (fastacl_bloomfilter_t *filter);
void fastacl_bloom_clear (fastacl_bloomfilter_t *filter);
void fastacl_bloom_stats (const fastacl_bloomfilter_t *filter,
                         fastacl_bloom_stats_t *stats);
int fastacl_bloom_window_init (fastacl_bloom_window_t *window,
                              const fastacl_bloom_plan_t *plan,
                              uint32_t validity_seconds, double now);
void fastacl_bloom_window_destroy (fastacl_bloom_window_t *window);
void fastacl_bloom_window_rotate (fastacl_bloom_window_t *window, double now);
/* Rotate on the main thread before learning after an elapsed epoch. Lookups
 * additionally check bank age, so a delayed timer cannot extend approval. */
void fastacl_bloom_window_learn_ip4 (fastacl_bloom_window_t *window,
                                   const uint8_t address[4]);
int fastacl_bloom_window_contains_ip4 (const fastacl_bloom_window_t *window,
                                      const uint8_t address[4], double now);

/* Explicit hash APIs: original C mixer and experimental multiply/fold.
 * Subnet learn/contains APIs select the mode stored in the filter. */
uint64_t fastacl_bloom_hash24 (uint32_t key);
uint64_t fastacl_bloom_hash24_fast (uint32_t key);
uint64_t fastacl_bloom_hash64 (uint64_t key);
uint64_t fastacl_bloom_hash64_fast (uint64_t key);
/* IPv4 addresses are four wire-order bytes, including unaligned packet data.
 * Both response destination learning and request source checks use this API.
 * The fourth octet is ignored: approval always covers the implied /24. */
uint64_t fastacl_bloom_hash_ip4_subnet (const uint8_t address[4]);
uint64_t fastacl_bloom_hash_ip4_subnet_fast (const uint8_t address[4]);
void fastacl_bloom_learn_ip4_subnet (fastacl_bloomfilter_t *filter,
                                   const uint8_t address[4]);
int fastacl_bloom_contains_ip4_subnet (const fastacl_bloomfilter_t *filter,
                                     const uint8_t address[4]);
void fastacl_bloom_insert (fastacl_bloomfilter_t *filter, uint64_t hash);
int fastacl_bloom_contains (const fastacl_bloomfilter_t *filter, uint64_t hash);

#endif
