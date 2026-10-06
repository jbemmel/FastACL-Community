/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <math.h>
#include <fastacl/members_only/bloomfilter.h>

static fastacl_bloomfilter_t filter;
static fastacl_bloomfilter_t subnet_filter;
static fastacl_bloomfilter_t other_zone;

static void
test_ip4_subnets (void)
{
  const uint8_t client[4] = { 198, 51, 100, 42 };
  uint8_t peer[4] = { 198, 51, 100, 0 };
  const uint8_t adjacent[4] = { 198, 51, 101, 42 };
  const uint8_t different_first[4] = { 199, 51, 100, 42 };
  const uint8_t different_second[4] = { 198, 52, 100, 42 };
  const uint8_t unaligned[5] = { 0, 198, 51, 100, 42 };

  assert (fastacl_bloom_hash_ip4_subnet (client) ==
          fastacl_bloom_hash24 (UINT32_C (0xc63364)));
  assert (fastacl_bloom_hash_ip4_subnet (unaligned + 1) ==
          fastacl_bloom_hash_ip4_subnet (client));
  assert (!fastacl_bloom_contains_ip4_subnet (&subnet_filter, client));
  fastacl_bloom_learn_ip4_subnet (&subnet_filter, client);
  for (unsigned host = 0; host < 256; host++)
    {
      peer[3] = host;
      assert (fastacl_bloom_contains_ip4_subnet (&subnet_filter, peer));
      assert (fastacl_bloom_hash_ip4_subnet (peer) ==
              fastacl_bloom_hash_ip4_subnet (client));
    }
  assert (!fastacl_bloom_contains_ip4_subnet (&subnet_filter, adjacent));
  assert (!fastacl_bloom_contains_ip4_subnet (&subnet_filter, different_first));
  assert (!fastacl_bloom_contains_ip4_subnet (&subnet_filter, different_second));
  assert (!fastacl_bloom_contains_ip4_subnet (&other_zone, client));
}

static uint64_t
reference_mix (uint64_t x)
{
  x ^= x >> 30;
  x *= UINT64_C (0xbf58476d1ce4e5b9);
  x ^= x >> 27;
  x *= UINT64_C (0x94d049bb133111eb);
  return x ^ (x >> 31);
}

static void
test_fast_hash (void)
{
  const uint64_t vectors[][2] = {
    { UINT64_C (0x0000000000000000), UINT64_C (0xcc6b94345120912a) },
    { UINT64_C (0x0000000000000001), UINT64_C (0x63f1a99fd66235fc) },
    { UINT64_C (0x00000000ffffffff), UINT64_C (0x240c67128c476b64) },
    { UINT64_C (0x0000000100000000), UINT64_C (0x4ba870c2f0aafcc7) },
    { UINT64_C (0x8000000000000000), UINT64_C (0x1ba0876194826312) },
    { UINT64_C (0xffffffffffffffff), UINT64_C (0x038bc7235edcd982) },
    { UINT64_C (0x13198a2e03707344), UINT64_C (0x0000000000000000) },
  };
  for (unsigned i = 0; i < sizeof (vectors) / sizeof (vectors[0]); i++)
    assert (fastacl_bloom_hash64_fast (vectors[i][0]) == vectors[i][1]);
  const uint8_t unaligned[5] = { 0, 198, 51, 100, 42 };
  assert (fastacl_bloom_hash_ip4_subnet_fast (unaligned + 1) ==
          fastacl_bloom_hash24_fast (UINT32_C (0xc63364)));
  for (uint32_t i = 0; i < 10000; i++)
    {
#if defined(__SIZEOF_INT128__)
      uint64_t key = UINT64_C (0x9e3779b97f4a7c15) * i;
      __uint128_t product = (__uint128_t) (key ^ UINT64_C (0x13198a2e03707344)) *
                             UINT64_C (0xa0761d6478bd642f);
      assert (fastacl_bloom_hash64_fast (key) ==
              ((uint64_t) product ^ (uint64_t) (product >> 64)));
#endif
      assert (fastacl_bloom_hash24_fast (i) ==
              fastacl_bloom_hash24_fast (i | UINT32_C (0xff000000)));
    }
}

static void *
insert_worker (void *arg)
{
  uintptr_t worker = (uintptr_t) arg;
  for (uint32_t i = 0; i < 10000; i++)
    fastacl_bloom_insert (&filter, fastacl_bloom_hash64 (i * 4 + worker));
  return NULL;
}

int
main (void)
{
  assert (fastacl_bloom_init (&filter, FASTACL_BLOOM_BITS,
                             FASTACL_BLOOM_PROBES) == 0);
  assert (fastacl_bloom_init (&subnet_filter, FASTACL_BLOOM_BITS,
                             FASTACL_BLOOM_PROBES) == 0);
  assert (fastacl_bloom_init (&other_zone, FASTACL_BLOOM_BITS,
                             FASTACL_BLOOM_PROBES) == 0);
  test_ip4_subnets ();
  test_fast_hash ();
  pthread_t threads[4];
  for (uint32_t i = 0; i < 10000; i++)
    {
      uint64_t x = UINT64_C (0x9e3779b97f4a7c15) * i;
      assert (fastacl_bloom_hash64 (x) ==
              reference_mix (x ^ UINT64_C (0x13198a2e03707344)));
      assert (fastacl_bloom_hash24 ((uint32_t) x) ==
              reference_mix ((x & UINT32_C (0xffffff)) ^
                             UINT64_C (0x243f6a8885a308d3)));
      assert (fastacl_bloom_hash24 (i) ==
              fastacl_bloom_hash24 (i | UINT32_C (0xff000000)));
    }
  assert (!fastacl_bloom_contains (&filter, fastacl_bloom_hash64 (0)));
  for (uintptr_t i = 0; i < 4; i++)
    assert (pthread_create (&threads[i], NULL, insert_worker, (void *) i) == 0);
  for (unsigned i = 0; i < 4; i++)
    assert (pthread_join (threads[i], NULL) == 0);
  for (uint32_t i = 0; i < 40000; i++)
    assert (fastacl_bloom_contains (&filter, fastacl_bloom_hash64 (i)));

  unsigned false_positives = 0;
  for (uint32_t i = 40000; i < 80000; i++)
    false_positives += fastacl_bloom_contains (&filter, fastacl_bloom_hash64 (i));
  /* Four probes and 40k entries in 1M bits should be comfortably below 1%. */
  assert (false_positives < 400);
  printf ("Bloom tests passed; %u/40000 false positives\n", false_positives);
  fastacl_bloom_destroy (&filter);
  fastacl_bloom_destroy (&subnet_filter);
  fastacl_bloom_destroy (&other_zone);
  return 0;
}
