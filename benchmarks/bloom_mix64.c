/* SPDX-License-Identifier: Apache-2.0
 * Standalone benchmark: see docs/bloom_mix64_benchmark.md.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "../src/plugins/fastacl/members_only/bloomfilter.c"

static volatile uint64_t sink;
/* Preserve the previous implementation as a benchmark baseline. */
static uint64_t asm_baseline(uint64_t x)
{
  const uint64_t m1 = UINT64_C(0xbf58476d1ce4e5b9);
  const uint64_t m2 = UINT64_C(0x94d049bb133111eb);
  x ^= x >> 30;
#if defined(__x86_64__)
  __asm__("imulq %1, %0" : "+r" (x) : "r" (m1) : "cc");
#else
  x *= m1;
#endif
  x ^= x >> 27;
#if defined(__x86_64__)
  __asm__("imulq %1, %0" : "+r" (x) : "r" (m2) : "cc");
#else
  x *= m2;
#endif
  return x ^ (x >> 31);
}
static uint64_t murmur(uint64_t x)
{
  x ^= x >> 33;
  x *= UINT64_C(0xff51afd7ed558ccd);
  x ^= x >> 33;
  x *= UINT64_C(0xc4ceb9fe1a85ec53);
  return x ^ (x >> 33);
}
static double now(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}
#define COUNT (1U << 22)
#define DEFINE(NAME, MIX) \
__attribute__((noinline)) static uint64_t NAME##_latency(void) \
{ uint64_t x = 1; for(unsigned i=0;i<COUNT;i++) x=MIX(x); return x; } \
__attribute__((noinline)) static uint64_t NAME##_throughput(void) \
{ uint64_t sum=0; for(unsigned i=0;i<COUNT;i++) \
    { sum += MIX((uint64_t)i ^ UINT64_C(0x243f6a8885a308d3)); } return sum; } \
__attribute__((noinline)) static uint64_t NAME##_lookup(fastacl_bloomfilter_t *f, unsigned start) \
{ uint64_t sum=0; for(unsigned i=0;i<COUNT;i++) \
    { sum += fastacl_bloom_contains(f, MIX(((i+start)&0xffffff) ^ UINT64_C(0x243f6a8885a308d3))); } return sum; } \
__attribute__((noinline)) static void NAME##_populate(fastacl_bloomfilter_t *f) \
{ for(unsigned i=0;i<100000;i++) fastacl_bloom_insert(f,MIX(i ^ UINT64_C(0x243f6a8885a308d3))); } \
__attribute__((noinline)) static uint64_t NAME##_hits(fastacl_bloomfilter_t *f) \
{ uint64_t sum=0; for(unsigned i=0;i<COUNT;i++) \
    { sum += fastacl_bloom_contains(f,MIX((i%100000) ^ UINT64_C(0x243f6a8885a308d3))); } return sum; } \
__attribute__((noinline)) static uint64_t NAME##_false_positives(fastacl_bloomfilter_t *f) \
{ uint64_t sum=0; for(unsigned i=100000;i<1100000;i++) \
    { sum += fastacl_bloom_contains(f,MIX(i ^ UINT64_C(0x243f6a8885a308d3))); } return sum; }
DEFINE(asm, asm_baseline)
DEFINE(c, fastacl_bloom_mix64)
DEFINE(murmur, murmur)
DEFINE(fold, fastacl_bloom_fold64)
struct variant {
  const char *name;
  uint64_t (*latency)(void), (*throughput)(void);
  uint64_t (*lookup)(fastacl_bloomfilter_t*,unsigned);
  void (*populate)(fastacl_bloomfilter_t*);
  uint64_t (*hits)(fastacl_bloomfilter_t*), (*false_positives)(fastacl_bloomfilter_t*);
};
#define ENTRY(N) {#N,N##_latency,N##_throughput,N##_lookup,N##_populate,N##_hits,N##_false_positives}
int main(void)
{
  for(uint64_t i=0;i<(1U<<24);i++)
    assert(fastacl_bloom_mix64(i ^ UINT64_C(0x243f6a8885a308d3)) ==
           asm_baseline(i ^ UINT64_C(0x243f6a8885a308d3)));
  fastacl_bloomfilter_t f={0};
  assert(!fastacl_bloom_init(&f, 1U<<21, 4));
  struct variant v[]={ENTRY(asm),ENTRY(c),ENTRY(murmur),ENTRY(fold)};
  puts("repeat,variant,workload,ns_per_key,checksum");
  for(unsigned j=0;j<4;j++) {
    fastacl_bloom_clear(&f); v[j].populate(&f);
    fprintf(stderr,"%s false positives: %llu/1000000\n",v[j].name,
            (unsigned long long)v[j].false_positives(&f));
  }
  for(unsigned r=0;r<9;r++)
    for(unsigned j=0;j<4;j++) {
      /* Rotate order to reduce systematic temperature/frequency bias. */
      struct variant *p=&v[(j+r)%4];
      fastacl_bloom_clear(&f); p->populate(&f);
      for(unsigned mode=0;mode<4;mode++) {
        double t=now();
        uint64_t result=mode==0?p->latency():mode==1?p->throughput():
          mode==2?p->lookup(&f,100000):p->hits(&f);
        t=now()-t; sink=result;
        printf("%u,%s,%s,%.5f,%llu\n",r,p->name,
               (const char*[]){"latency","throughput","lookup_miss","lookup_hit"}[mode],
               t*1e9/COUNT,(unsigned long long)result);
      }
    }
  fastacl_bloom_destroy(&f);
}
