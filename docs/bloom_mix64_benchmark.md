# Bloom mixer benchmark

Measured October 6, 2026 on Intel Core i7-10850H (Comet Lake), GCC
13.3.0, Linux x86-64, pinned to logical CPU 2. Recommendation: replace the
inline assembly multiplications with ordinary unsigned C multiplications.
The assembly provides no demonstrated scalar advantage on this machine and
prevents GCC from vectorizing independent hashes in the native build.
Production code uses ordinary C multiplication for the original mixer and
also provides the experimental fold mixer. Per-zone `fast_hashing` defaults to
`1` (fold); `0` selects the original C mixer. The benchmark retains the previous
assembly implementation locally for reproducible comparisons.

The benchmark includes the production source to exercise the actual static
mixer and Bloom operations. It compares assembly, the equivalent C sequence,
MurmurHash3's 64-bit finalizer, and an experimental multiply/fold expression:

```c
__uint128_t p = (__uint128_t)x * UINT64_C(0xa0761d6478bd642f);
return (uint64_t)p ^ (uint64_t)(p >> 64);
```

This expression is now available as the experimental option; it is not a
validated general purpose replacement or a claim to implement a complete named
hash algorithm. The benchmark fold variant calls the production fold helper.

## Results

Median nanoseconds per key across nine repetitions, each with 4,194,304
operations. Lower is better. Variant order rotates each repetition.

Previous repository optimization level (`-O2`, default x86-64 target):

| Mixer | Dependency chain | Independent hashes | Bloom miss query | Bloom hit query |
|---|---:|---:|---:|---:|
| Previous assembly | 2.634 | 0.806 | 4.378 | 5.370 |
| Equivalent C | 2.698 | 0.777 | 4.354 | 5.485 |
| Murmur finalizer | 2.679 | 0.788 | 4.398 | 5.371 |
| Multiply/fold | 1.097 | 0.466 | 3.863 | 4.877 |

Native throughput experiment (`-O3 -march=native`):

| Mixer | Dependency chain | Independent hashes | Bloom miss query | Bloom hit query |
|---|---:|---:|---:|---:|
| Previous assembly | 2.611 | 0.750 | 4.180 | 5.331 |
| Equivalent C | 2.652 | 0.521 | 4.258 | 5.302 |
| Murmur finalizer | 2.567 | 0.517 | 4.189 | 5.348 |
| Multiply/fold | 1.078 | 0.587 | 3.607 | 4.858 |

At `-O2`, assembly and C dependency loops have identical instruction bytes
apart from placement/branch addresses. Both use register `imul` with the
same constants and shifts. Ordinary C already needs no optional ISA or
runtime dispatch. The small timing differences are not evidence of a useful
assembly advantage; frequency and shared-host noise remain uncontrolled.

At `-O3 -march=native`, disassembly shows AVX2 vector operations in the C
independent-hash loop and scalar operations in the assembly loop. C takes
about 31% less time per independent hash. This benefit requires an inlined
batch of independent inputs: it is not a measured improvement to the current
out-of-line packet hashing API. The Bloom loops do not show a consistent
assembly-versus-C advantage.

Multiply/fold takes about 42% less time for independent hashes at `-O2`,
58% less for the dependency chain, and 9–12% less for these Bloom queries.
Murmur offers no clear scalar benefit over the existing mixer.

## Workloads and correctness

The chain feeds each mixer output into the next input, measuring serialized
work rather than normal packet throughput. Independent hashes use sequential
24-bit keys with the production hash24 seed. They include summation overhead;
reported times are not isolated instruction latencies. Bloom queries use
2,097,152 bits (256 KiB), four probes and 100,000 inserted sequential prefixes.
Miss queries cover subsequent uninserted prefixes; false positives still
return hits. Hit queries cycle over inserted prefixes and include the cost
of reducing the index modulo 100,000. Each variant populates its own filter
with its own hashes. Setup is outside timed regions. Checksums are consumed
through a volatile sink; functions are noinline to prevent hoisting whole
benchmark calls.

Assembly/C equivalence is checked over every one of the 16,777,216 IPv4 /24
identities. Existing Bloom and configuration tests also pass, including
reference comparisons for 64-bit inputs. One million uninserted sequential
prefixes yield these false-positive counts:

| Mixer | False positives / 1,000,000 |
|---|---:|
| Assembly / equivalent C | 902 |
| Murmur finalizer | 915 |
| Multiply/fold | 861 |

This limited distribution check does not establish multiply/fold avalanche
quality, independence of low/high halves, or robustness across sparse,
structured and adversarial 64-bit keys. Before adopting a different mixer,
validate those properties and Bloom false-positive rates across configured
sizes/probe counts and representative traffic. Changing a hash requires
clearing/rebuilding any existing filter populated with the old hash.

These are single-thread, warm-filter microbenchmarks, not complete VPP
packet-path measurements. They omit address extraction, two-bank expiry,
contention, cold-memory behavior, and packet scheduling. Only GCC on this CPU
was measured; Clang is unavailable. Removing assembly is the smallest change
with identical hash outputs. Batching hashes in C is a promising subsequent
optimization; adopting multiply/fold needs broader quality validation first.

Current Release builds use `-O3`, loop unrolling, frame-pointer omission and
supported LTO, while retaining VPP CPU variants. The historical tables above
do not measure that complete production build configuration.

## Reproduce

From the repository root (choose an available CPU in place of `2`):

```sh
gcc -O2 -Wall -Wextra -Werror -I src/plugins benchmarks/bloom_mix64.c -lm -o /tmp/bloom-bench-o2
taskset -c 2 /tmp/bloom-bench-o2 > /tmp/bloom-o2.csv
gcc -O3 -march=native -Wall -Wextra -Werror -I src/plugins benchmarks/bloom_mix64.c -lm -o /tmp/bloom-bench-native
taskset -c 2 /tmp/bloom-bench-native > /tmp/bloom-native.csv
objdump -d /tmp/bloom-bench-o2 --disassemble=asm_latency
objdump -d /tmp/bloom-bench-o2 --disassemble=c_latency
objdump -d /tmp/bloom-bench-native --disassemble=c_throughput
```

Do not compile with `-DNDEBUG`: assertions perform equivalence checks and
filter initialization. Raw measurements are saved in
`benchmarks/bloom_mix64_gcc13_o2.csv` and
`benchmarks/bloom_mix64_gcc13_native.csv`.
