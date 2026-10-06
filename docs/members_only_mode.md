# Members-only mode: concept and first prototype

Members-only mode is designed to provide efficient, scalable source-network
admission for multi-tenant fabrics with high change rates. The intended design
scopes membership to each tenant's protected services and keeps admission
lookups bounded as validated users, source networks, and service populations
change. It learns networks used by validated users during normal operation,
then restricts a protected service to the last trusted membership set during a
DDoS attack. Membership permits a packet to continue through the remaining
FastACL rules and service checks; it does not bypass them.

The design moves validation, routing context, and coverage compilation out of
the packet path, then publishes compact membership generations for packet
lookups. This separates frequent membership changes from per-packet work.
Tenant and service scope must be part of the membership key or select separate
storage, so learning for one tenant cannot authorize access to another.
High-change-rate evaluation must measure update throughput and publication
pauses alongside lookup cost and memory per tenant; these are design goals,
not performance claims for the first prototype.

The first prototype implements named zones, configurable IPv4 /24 Bloom-filter
storage, approximate expiry, lifecycle management, and an inspection CLI.
Creating a zone currently does not change packet admission. The learning and
lookup routines are available to C callers and exercised by tests, but packet
learning, service matching, and enforcement are not wired into the dataplane.

## Implementation status

| Capability | First prototype |
| --- | --- |
| Named zones and configuration | Implemented; each zone owns independent storage |
| IPv4 /24 insertion and membership lookup | Implemented as C routines; not connected to packet processing |
| Automatic or explicit Bloom sizing | Implemented; CLI explicit size is a log2 bit count |
| Approximate expiry, reset, deletion, inspection | Implemented |
| Trusted learning signals and target/service matching | Not implemented, including TCP-option signal rules |
| Enable/disable enforcement and freeze/recovery transitions | Not implemented |
| BGP/FRR/Bird or attestation integration and coverage compilation | Concept only |
| IPv6 membership and exact longest-prefix admission | Concept only |

## Admission concept

The intended membership set is effectively a source route table scoped to a
protected service. A lookup uses the packet's source IP, and longest-prefix
matching selects the admission result rather than a next hop. Each record
carries a prefix, admission result, and provenance. A miss rejects the source
in members-only mode, and a more-specific entry takes precedence over a broader
one. The prototype approximates membership with fixed IPv4 /24 buckets instead
of implementing this exact route-table model.

The following learning, transition, and compilation sections describe the
intended full design. They are not behaviors enabled by the prototype CLI.

## Learning valid sources

Learning should be scoped to a protected service or destination prefix, so a
source observed using one service does not automatically gain access to every
protected service. A valid-user signal should come from successful application
interactions or another trusted validation mechanism. Merely receiving a packet
from an IP address is insufficient: spoofed packets and attack traffic must not
populate the admission set.

For each validated source IP, the learner associates the address with a BGP
prefix supplied by the control plane associated with VPP, typically FRR or
Bird. This requires an integration that exports routing information to the
learner; it should not assume VPP's forwarding table carries all BGP attributes.
The lookup should use the most-specific applicable route in the relevant
routing context, with an explicit policy for missing routes. A default route
must not turn a single observed user into permission for the entire Internet.

The concept can be framed as a form of RPKI on a per-user basis: a trusted
authority attests which source prefixes are authorized for a particular user
or user population accessing a protected service. This is a proposed analogy,
not an implementation of the RPKI protocol. The admission decision binds a
validated user to an authorized source prefix, with BGP origin and AS-path
information providing additional routing context.

Netom is an example of a trusted source that a deployment could use for these
user-prefix origin attestations. Record the user or population identifier,
authorized prefixes, issuer, validity period, and verification evidence
alongside the routing context. Verify attestations and apply expiration or
revocation policy during peace-time compilation. Origin information alone
does not establish that a user is valid or authorize additions to the frozen
set in members-only mode. Any attack-time revocation mechanism would need an
explicit policy for narrowing access without admitting new sources.

Candidate records can include:

- Source IP, address family, protected service, and associated BGP prefix.
- First and last validated observation, observation count, and validation method.
- Routing context, route snapshot version, and observation time.
- Origin AS, AS path, and changes to those attributes over time, when available.
- Normal traffic characteristics, such as request rate and protocol mix.

AS-path history and other metadata can help establish normal traffic patterns
and flag unexpected changes. They are control-plane evidence for admission
policy, rather than fields available in each arriving packet. A BGP prefix is
also a network grouping, not proof that every address within it is a valid user.

## Modes and transitions

| Mode | Source validation | Learning and admission updates |
| --- | --- | --- |
| Peace time | Observe validated users and evaluate candidate coverage | Learn, age records, compile, and publish trusted generations |
| Members-only mode | Require admission from the longest matching source prefix in the frozen table | Read-only; no new sources, widening, or record expiration |
| Recovery | Continue enforcing the frozen set while checking attack clearance | Resume learning only after an explicit transition to peace time |

An external detector or operator enables members-only mode. The transition must freeze
the latest trusted published generation and stop admission updates atomically.
An in-progress compilation must not become active after the freeze. Attack-time
observations may be retained separately for analysis, but must not alter the
trusted learning records or admission set.

In members-only mode, a lookup miss or a rejecting longest-prefix match is rejected
for the protected scope. An admitting longest-prefix match is eligible to
proceed through the remaining FastACL rules and service checks; admission must
not bypass other mitigation. Addresses covered by an admitted prefix will match
even if they were never observed individually, unless a more-specific entry
rejects them. Thus
"no new sources" means no additions to the frozen coverage set; enforcing it
literally per user address requires exact /32 or /128 entries.

Route changes during an attack must not automatically expand or remap the
frozen set. They can generate alerts for operator review. Returning to learning
should require a sustained attack-free interval or an explicit operator action,
with hysteresis to avoid repeated learning/enforcement transitions. If no
trusted generation exists, members-only mode needs a configured bootstrap policy, such
as a manually curated set; it must not learn from the attack to fill the gap.

## Compiling a reasonable coverage set

The peace-time compiler converts validated observations into a coverage set
that balances access for legitimate users against CPU cost per request and
memory use. The BGP prefix provides context and a candidate grouping; it need
not be the exact prefix admitted into the data plane.

Exact /32 and /128 entries give narrow admission but can produce large tables
and exclude users whose addresses change. Broader prefixes cover such changes
and reduce entry count, but also admit unobserved addresses and potential
attackers in the same network. Aggregation should therefore be governed by
explicit limits on coverage expansion, observation density, record freshness,
and routing stability. Combining adjacent entries into a parent prefix should
require evidence or policy authorizing the additional address space.

The compiler should remove entries only when doing so preserves longest-prefix
admission decisions, select a bounded set of prefix
lengths, and estimate legitimate-user coverage and additional admitted address
space. A smaller number of entries does not necessarily imply a cheaper
lookup: the number of prefix lengths probed, cache behavior, and table load
factor also matter. IPv4 and IPv6 require separate coverage policies; IPv6
address-space size makes raw address counts a poor substitute for observed
user coverage.

## Hash-based source validation

### Simplified members-only mode with a Bloom filter

The members-only implementation could use a Bloom filter keyed by the top 24 bits
of an IPv4 source address or the top 64 bits of an IPv6 source address. This
normalizes sources to /24 and /64 buckets respectively, allowing a fixed
number of hash operations without probing multiple prefix lengths. Use separate
filters per address family and protected service, or include that scope in the
hashed key.

During peace time, the compiler ensures that every valid IPv4 /24 subnet and
IPv6 /64 bucket is present in the filter. A valid source more specific than
the bucket size contributes its containing bucket; a broader admitted prefix
requires insertion of every bucket it covers. The compiler must budget for
this expansion, especially for broad IPv6 prefixes, and publish only complete
generations. It freezes the completed filter when members-only mode begins.

In members-only mode, a negative lookup rejects the source. A positive lookup admits
it to the remaining FastACL rules and service checks. A correctly compiled
Bloom filter has no false negatives for inserted buckets, but false positives
can admit buckets that were never inserted. In addition, every address within
an inserted bucket is covered, including users not individually observed.
Choose the filter size and number of hash functions against the bucket count,
acceptable false-positive rate, memory budget, and CPU cost per packet.

This is an approximate compilation of the source route admission policy:
it does not perform longest-prefix matching at runtime. The compiler must
explicitly account for lost precision when reducing policy to bucket
membership. A Bloom filter alone cannot preserve a more-specific rejection
inside an admitted bucket. Deployments requiring those exceptions or exact
admission can retain the exact source route lookup, optionally using the Bloom
filter to reject definite misses before that lookup.

### Exact longest-prefix lookup

A candidate implementation groups source route entries by address family and
prefix length. Each group contains an optimized hash table keyed by the masked
network address and protected scope. For a packet source, the data plane masks
the address for each active length and probes the corresponding table in
descending prefix-length order. The first match is the longest-prefix match,
and its admission result determines whether the source may access the service.
A broader admitting entry must not override a more-specific rejecting entry.
If no entry matches, admission fails in members-only mode.

The compiler should cap the number of active prefix lengths to keep the number
of probes bounded, especially on misses during an attack. It can select a small
set of lengths or evaluate a fixed-stage hash scheme, provided the resulting
coverage remains within policy and longest-prefix decisions are preserved.
Hash collisions in the exact tables must be resolved with full-key comparison.
Unlike the simplified Bloom-filter option, this path preserves exact admission
decisions without probabilistic false positives.

Compilation happens outside the packet-processing path. It produces an
immutable generation containing the tables, masks, scope identifiers, and
summary metadata. Publication should switch generations atomically using VPP's
appropriate worker synchronization mechanism, and retire the previous tables
only after workers can no longer reference them. The packet path performs no
learning, routing queries, AS-path processing, or table resizing.

## Operational evaluation

Before enabling enforcement, run a candidate generation in observation mode
and measure how many validated users it would exclude. Evaluate representative
IPv4 and IPv6 traffic, changing client addresses, sparse and dense source
networks, and attack traffic dominated by lookup misses.

Track legitimate-user coverage, admitted address-space expansion, table memory,
active prefix lengths, probes per lookup, cycles per packet, and throughput.
Expose the active generation, learning freeze state, record age, and per-scope
hit/miss counters so operators can explain an admission decision and roll back
to a previous trusted generation.

The main tradeoff is intentional: a frozen set protects the service from new
source networks during an attack, while some legitimate new users will be
excluded. Broadening coverage improves access but admits more possible attack
sources. Members-only mode is therefore one mitigation layer, with its coverage
and lookup budget chosen for the protected service.

## First prototype architecture

The implementation lives in `src/plugins/fastacl/members_only/`:

- `bloomfilter.c` and `bloomfilter.h` implement sizing, allocation, hashing,
  insertion, lookup, occupancy statistics, and rotating filter windows.
- `members_only.c` and `members_only.h` implement the zone registry, CLI,
  worker synchronization, and periodic expiry maintenance.

Each zone stores its name, requested configuration, effective sizing plan, and
one or two filter banks. Names accept 1..63 letters, digits, hyphens, or
underscores. A name currently identifies storage only; it does not bind a zone
to a destination prefix, interface, or service.

IPv4 helpers read four wire-order bytes, including unaligned addresses, and
ignore the fourth octet. Learning `198.51.100.42` therefore covers the entire
`198.51.100.0/24`. Concurrent insertion uses atomic bit updates, and lookups use
atomic loads. Clear, rotation, destruction, and reconfiguration require readers
and writers to be stopped; the zone layer uses VPP worker barriers for these
operations. Callers must initialize filter structures before use and rotate
expired epochs on the main thread before further learning.

A positive lookup is approximate membership, not authentication. Inserted
buckets have no Bloom false negatives while their bank remains valid, but
expiry and reset intentionally remove approvals. False positives can report
membership for a bucket that was never inserted. There is no original-key
store, individual deletion, exact exception table, or persistent membership
store in this prototype.

The CLI converts `bloom bits <log2>` to an actual bit count before planning.
The C configuration and plan fields retain actual bit counts; `config.bits = 0`
selects automatic sizing. Inspection also reports actual bits per bank.

Expiry currently continues independently of any attack state. The proposed
members-only transition must freeze both learning and expiration; no such
transition exists yet. `validity-window 0` disables expiry but still allows C
callers to insert entries, so it does not implement frozen membership.

## Configure a zone

Automatic sizing:

```text
fastacl members-only zone website bloom expected-subnets 100000 false-positive-rate 0.001 validity-window 30m
show fastacl members-only website
```

Capacity counts distinct approved /24 subnets, not individual addresses or
validation events. Repeated learning of the same subnet does not add occupancy.
Defaults are 100,000 subnets, a 0.001 target rate, a 30-minute validity window,
a 16 MiB storage limit, and `fast_hashing 1`.
`fastacl members-only zone website` uses those defaults.

`fast_hashing` is a per-zone boolean: `1` enables the experimental full-width
multiply/fold mixer; `0` selects the original C avalanche mixer. Both learning
and lookup use the selected mode, including both expiry banks. Changing the
mode on an existing zone requires `reset`, which discards learned approvals.
For example, to select the original mixer with the other default settings:

```text
fastacl members-only zone website fast_hashing 0 reset
```

The fold mixer is faster in the [local benchmark](bloom_mix64_benchmark.md),
but its hash quality has only limited validation. Automatic sizing and reported
false-positive estimates use the same statistical distribution assumptions
for either mixer. The implementation produces the same fold result with native
128-bit multiplication or a portable 32-bit-limb fallback.

Automatic sizing searches power-of-two bit counts and selects the smallest
allocation meeting the estimated false-positive target with at most 16 probes.
Within that allocation it selects the smallest probe count meeting the target,
reducing packet work rather than always choosing the mathematically optimal
probe count. The familiar estimates are:

```text
bits   = -capacity * ln(rate) / ln(2)^2
probes = bits / capacity * ln(2)
rate   ≈ (1 - exp(-probes * capacity / bits))^probes
```

The implementation evaluates the last expression for integer probe counts.
Expiry uses two filters, and automatic sizing budgets each bank for the full
expected subnet count and half the zone target rate. Summing the two bank
estimates gives a conservative combined bound without assuming independence.
The example allocates 2,097,152 bits per bank, 5 probes, and 524,288 bytes total.
These are statistical estimates under the hash-distribution assumption, not
guarantees against adversarial traffic. See the
[Kirsch–Mitzenmacher Bloom-filter analysis](https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf).

Explicit sizing:

```text
fastacl members-only zone laboratory bloom bits 20 probes 4 validity-window 0 memory-limit-mb 16
```

`bits` is the **log2 bit count per bank**, accepts 6..29 (64..536,870,912
bits), and requires `probes` in 1..16. For example, `bits 20` allocates
2^20 = 1,048,576 bits per bank. Explicit sizing does not accept `false-positive-rate`:
the displayed rate is an estimate for the configured capacity, not a target.
`bloom expected-subnets` can also be supplied with explicit sizing to set the
capacity used for estimates. Automatic sizing rejects an unattainable target
instead of silently lowering accuracy to fit a memory limit.

Durations accept whole seconds or one suffix (`s`, `m`, `h`, `d`). Supported
windows are 2 seconds through 365 days, or `0` for no expiry. `memory-limit-mb`
accepts 1..64 MiB and includes every bank's bit storage. Up to 64 zones and
256 MiB total Bloom storage are allowed; replacement storage also counts toward
the total while allocated. Small metadata allocations are additional.

## Expiry and reset

With a nonzero validity window, learning writes to the active bank. Banks rotate
every half window, and queries test either bank separately. A subnet learned
near the start of an epoch lives for approximately a full window; one learned
near its end lives for approximately half a window. Refreshing approval inserts
the subnet into the current bank. Approximate expiry may therefore require
revalidation before the full configured window has elapsed. It is not a strict
per-subnet TTL.

A VPP process checks rotation every 0.5 seconds and clears/reuses banks under a
worker barrier. Queries also check bank age, so delayed maintenance cannot
extend approvals beyond the configured window. A delay can shorten the lifetime
of a newly learned subnet, since the active epoch has not yet advanced. Long
process delays clear both old banks rather than resurrecting stale approvals.
Clearing large filters under a barrier briefly pauses workers.

With `validity-window 0`, one bank is allocated and entries remain until reset
or deletion. Rotation is disabled. This setting alone does not freeze learning.

Resizing cannot preserve learned entries: this implementation does not retain
the original keys. Reconfiguring an existing zone requires an explicit reset:

```text
fastacl members-only zone website bloom expected-subnets 200000 false-positive-rate 0.001 validity-window 1h reset
fastacl members-only delete laboratory
```

All supplied settings form a complete replacement; omitted settings return to
defaults. Reset discards all approvals and rotation history. Invalid settings
or allocation failure leave the previous zone intact. Publication, deletion,
reset and rotation synchronize with workers; do not cache zone pointers across
configuration changes.

## Inspect a zone

`show fastacl members-only [name]` reports effective bit count, probes, bank count,
storage usage and limits, capacity, planned rate, hash mode (`fast_hashing`),
expiry window and rotations.
Each bank also reports occupancy, estimated distinct subnets and estimated
false-positive rate. The command flags exceeded capacity and automatic rate
targets. Per-bank cardinality estimates overlap and should not be summed into
an exact zone-wide count. A full bank reports saturated estimated cardinality
and a false-positive estimate of 1.

Occupancy is computed from atomic bit loads when requested; there is no extra
shared counter update per packet. During concurrent learning, these readings
are approximate snapshots. Actual traffic false positives cannot be measured
without an exact reference set. Each zone owns separate storage.

## Build and test

```sh
cmake -S . -B build/devcontainer -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build/devcontainer
ctest --test-dir build/devcontainer --output-on-failure
```

The standalone filter tests cover concurrent learning, /24 normalization,
explicit dimensions, auto sizing, invalid configuration, occupancy, resets and
rotation boundary/catch-up behavior. They keep assertions enabled in release
builds. A CLI parsing and zone-lifecycle harness is also built when VPP runtime
libraries are installed; VPP development headers alone are sufficient for the
standalone tests. Configuration fields and routines are exposed in `members_only.h` and
`bloomfilter.h` for the subsequent signal/enforcement integration.
