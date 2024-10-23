# Hardened malloc

* [Introduction](#introduction)
* [Dependencies](#dependencies)
* [Testing](#testing)
    * [Individual Applications](#individual-applications)
    * [Automated Test Framework](#automated-test-framework)
* [Compatibility](#compatibility)
* [OS integration](#os-integration)
    * [Android-based operating systems](#android-based-operating-systems)
    * [Traditional Linux-based operating systems](#traditional-linux-based-operating-systems)
* [Configuration](#configuration)
* [Core design](#core-design)
* [Security properties](#security-properties)
* [Randomness](#randomness)
* [Size classes](#size-classes)
* [Scalability](#scalability)
    * [Small (slab) allocations](#small-slab-allocations)
        * [Thread caching (or lack thereof)](#thread-caching-or-lack-thereof)
    * [Large allocations](#large-allocations)
* [Memory tagging](#memory-tagging)
* [API extensions](#api-extensions)
* [Stats](#stats)
* [System calls](#system-calls)

## Introduction

This is a security-focused general purpose memory allocator providing the
malloc API along with various extensions. It provides substantial hardening
against heap corruption vulnerabilities. The security-focused design also leads
to much less metadata overhead and memory waste from fragmentation than a more
traditional allocator design. It aims to provide decent overall performance
with a focus on long-term performance and memory usage rather than allocator
micro-benchmarks. It offers scalability via a configurable number of entirely
independent arenas, with the internal locking within arenas further divided
up per size class.

This project currently supports Bionic (Android), musl and glibc. It may
support other non-Linux operating systems in the future. For Android, there's
custom integration and other hardening features which is also planned for musl
in the future. The glibc support will be limited to replacing the malloc
implementation because musl is a much more robust and cleaner base to build on
and can cover the same use cases.

This allocator is intended as a successor to a previous implementation based on
extending OpenBSD malloc with various additional security features. It's still
heavily based on the OpenBSD malloc design, albeit not on the existing code
other than reusing the hash table implementation. The main differences in the
design are that it's solely focused on hardening rather than finding bugs, uses
finer-grained size classes along with slab sizes going beyond 4k to reduce
internal fragmentation, doesn't rely on the kernel having fine-grained mmap
randomization and only targets 64-bit to make aggressive use of the large
address space. There are lots of smaller differences in the implementation
approach. It incorporates the previous extensions made to OpenBSD malloc
including adding padding to allocations for canaries (distinct from the current
OpenBSD malloc canaries), write-after-free detection tied to the existing
clearing on free, queues alongside the existing randomized arrays for
quarantining allocations and proper double-free detection for quarantined
allocations. The per-size-class memory regions with their own random bases were
loosely inspired by the size and type-based partitioning in PartitionAlloc. The
planned changes to OpenBSD malloc ended up being too extensive and invasive so
this project was started as a fresh implementation better able to accomplish
the goals. For 32-bit, a port of OpenBSD malloc with small extensions can be
used instead as this allocator fundamentally doesn't support that environment.

## Dependencies

Debian stable (currently Debian 12) determines the most ancient set of
supported dependencies:

* glibc 2.36
* Linux 6.1
* Clang 14.0.6 or GCC 12.2.0

For Android, the Linux GKI 5.10, 5.15 and 6.1 branches are supported.

However, using more recent releases is highly recommended. Older versions of
the dependencies may be compatible at the moment but are not tested and will
explicitly not be supported.

For external malloc replacement with musl, musl 1.1.20 is required. However,
there will be custom integration offering better performance in the future
along with other hardening for the C standard library implementation.

For Android, only the current generation, actively developed maintenance branch of the Android
Open Source Project will be supported, which currently means `android15-release`.

## Testing

### Individual Applications

The `preload.sh` script can be used for testing with dynamically linked
executables using glibc or musl:

    ./preload.sh krita --new-image RGBA,U8,500,500

It can be necessary to substantially increase the `vm.max_map_count` sysctl to
accommodate the large number of mappings caused by guard slabs and large
allocation guard regions. The number of mappings can also be drastically
reduced via a significant increase to `CONFIG_GUARD_SLABS_INTERVAL` but the
feature has a low performance and memory usage cost so that isn't recommended.

It can offer slightly better performance when integrated into the C standard
library and there are other opportunities for similar hardening within C
standard library and dynamic linker implementations. For example, a library
region can be implemented to offer similar isolation for dynamic libraries as
this allocator offers across different size classes. The intention is that this
will be offered as part of hardened variants of the Bionic and musl C standard
libraries.

### Automated Test Framework

A collection of simple, automated tests are provided and can be run with the
make command as follows:

    make test

## Compatibility

OpenSSH 8.1 or higher is required to allow the mprotect `PROT_READ|PROT_WRITE`
system calls in the seccomp-bpf filter rather than killing the process.

## OS integration

### Android-based operating systems

On GrapheneOS, hardened\_malloc is integrated into the standard C library as
the standard malloc implementation. Other Android-based operating systems can
reuse [the integration
code](https://github.com/GrapheneOS/platform_bionic/commit/20160b81611d6f2acd9ab59241bebeac7cf1d71c)
to provide it. If desired, jemalloc can be left as a runtime configuration
option by only conditionally using hardened\_malloc to give users the choice
between performance and security. However, this reduces security for threat
models where persistent state is untrusted, i.e. verified boot and attestation
(see the [attestation sister project](https://attestation.app/about)).

Make sure to raise `vm.max_map_count` substantially too to accommodate the very
large number of guard pages created by hardened\_malloc. This can be done in
`init.rc` (`system/core/rootdir/init.rc`) near the other virtual memory
configuration:

    write /proc/sys/vm/max_map_count 1048576

This is unnecessary if you set `CONFIG_GUARD_SLABS_INTERVAL` to a very large
value in the build configuration.

### Traditional Linux-based operating systems

On traditional Linux-based operating systems, hardened\_malloc can either be
integrated into the libc implementation as a replacement for the standard
malloc implementation or loaded as a dynamic library. Rather than rebuilding
each executable to be linked against it, it can be added as a preloaded
library to `/etc/ld.so.preload`. For example, with `libhardened_malloc.so`
installed to `/usr/local/lib/libhardened_malloc.so`, add that full path as a
line to the `/etc/ld.so.preload` configuration file:

    /usr/local/lib/libhardened_malloc.so

The format of this configuration file is a whitespace-separated list, so it's
good practice to put each library on a separate line.

On Debian systems `libhardened_malloc.so` should be installed into `/usr/lib/`
to avoid preload failures caused by AppArmor profile restrictions.

Using the `LD_PRELOAD` environment variable to load it on a case-by-case basis
will not work when `AT_SECURE` is set such as with setuid binaries. It's also
generally not a recommended approach for production usage. The recommendation
is to enable it globally and make exceptions for performance critical cases by
running the application in a container / namespace without it enabled.

Make sure to raise `vm.max_map_count` substantially too to accommodate the very
large number of guard pages created by hardened\_malloc. As an example, in
`/etc/sysctl.d/hardened_malloc.conf`:

    vm.max_map_count = 1048576

This is unnecessary if you set `CONFIG_GUARD_SLABS_INTERVAL` to a very large
value in the build configuration.

On arm64, make sure your kernel is configured to use 4k pages since we haven't
yet added support for 16k and 64k pages. The kernel also has to be configured
to use 4 level page tables for the full 48 bit address space instead of only
having a 39 bit address space for the default hardened\_malloc configuration.
It's possible to reduce the class region size substantially to make a 39 bit
address space workable but the defaults won't work.

## Configuration

You can set some configuration options at compile-time via arguments to the
make command as follows:

    make CONFIG_EXAMPLE=false

Configuration options are provided when there are significant compromises
between portability, performance, memory usage or security. The core design
choices are not configurable and the allocator remains very security-focused
even with all the optional features disabled.

The configuration system supports a configuration template system with two
standard presets: the default configuration (`config/default.mk`) and a light
configuration (`config/light.mk`). Packagers are strongly encouraged to ship
both the standard `default` and `light` configuration. You can choose the
configuration to build using `make VARIANT=light` where `make VARIANT=default`
is the same as `make`. Non-default configuration templates will build a library
with the suffix `-variant` such as `libhardened_malloc-light.so` and will use
an `out-variant` directory instead of `out` for the build.

The `default` configuration template has all normal optional security features
enabled (just not the niche `CONFIG_SEAL_METADATA`) and is quite aggressive in
terms of sacrificing performance and memory usage for security. The `light`
configuration template disables the slab quarantines, write after free check,
slot randomization and raises the guard slab interval from 1 to 8 but leaves
zero-on-free and slab canaries enabled. The `light` configuration has solid
performance and memory usage while still being far more secure than mainstream
allocators with much better security properties. Disabling zero-on-free would
gain more performance but doesn't make much difference for small allocations
without also disabling slab canaries. Slab canaries slightly raise memory use
and slightly slow down performance but are quite important to mitigate small
overflows and C string overflows. Disabling slab canaries is not recommended
in most cases since it would no longer be a strict upgrade over traditional
allocators with headers on allocations and basic consistency checks for them.

For reduced memory usage at the expense of performance (this will also reduce
the size of the empty slab caches and quarantines, saving a lot of memory,
since those are currently based on the size of the largest size class):

    make \
    N_ARENA=1 \
    CONFIG_EXTENDED_SIZE_CLASSES=false

The following boolean configuration options are available:

* `CONFIG_WERROR`: `true` (default) or `false` to control whether compiler
  warnings are treated as errors. This is highly recommended, but it can be
  disabled to avoid patching the Makefile if a compiler version not tested by
  the project is being used and has warnings. Investigating these warnings is
  still recommended and the intention is to always be free of any warnings.
* `CONFIG_NATIVE`: `true` (default) or `false` to control whether the code is
  optimized for the detected CPU on the host. If this is disabled, setting up a
  custom `-march` higher than the baseline architecture is highly recommended
  due to substantial performance benefits for this code.
* `CONFIG_CXX_ALLOCATOR`: `true` (default) or `false` to control whether the
  C++ allocator is replaced for slightly improved performance and detection of
  mismatched sizes for sized deallocation (often type confusion bugs). This
  will result in linking against the C++ standard library.
* `CONFIG_ZERO_ON_FREE`: `true` (default) or `false` to control whether small
  allocations are zeroed on free, to mitigate use-after-free and uninitialized
  use vulnerabilities along with purging lots of potentially sensitive data
  from the process as soon as possible. This has a performance cost scaling to
  the size of the allocation, which is usually acceptable. This is not relevant
  to large allocations because the pages are given back to the kernel.
* `CONFIG_WRITE_AFTER_FREE_CHECK`: `true` (default) or `false` to control
  sanity checking that new small allocations contain zeroed memory. This can
  detect writes caused by a write-after-free vulnerability and mixes well with
  the features for making memory reuse randomized / delayed. This has a
  performance cost scaling to the size of the allocation, which is usually
  acceptable. This is not relevant to large allocations because they're always
  a fresh memory mapping from the kernel.
* `CONFIG_SLOT_RANDOMIZE`: `true` (default) or `false` to randomize selection
  of free slots within slabs. This has a measurable performance cost and isn't
  one of the important security features, but the cost has been deemed more
  than acceptable to be enabled by default.
* `CONFIG_SLAB_CANARY`: `true` (default) or `false` to enable support for
  adding 8 byte canaries to the end of memory allocations. The primary purpose
  of the canaries is to render small fixed size buffer overflows harmless by
  absorbing them. The first byte of the canary is always zero, containing
  overflows caused by a missing C string NUL terminator. The other 7 bytes are
  a per-slab random value. On free, integrity of the canary is checked to
  detect attacks like linear overflows or other forms of heap corruption caused
  by imprecise exploit primitives. However, checking on free will often be too
  late to prevent exploitation so it's not the main purpose of the canaries.
* `CONFIG_SEAL_METADATA`: `true` or `false` (default) to control whether Memory
  Protection Keys are used to disable access to all writable allocator state
  outside of the memory allocator code. It's currently disabled by default due
  to a significant performance cost for this use case on current generation
  hardware, which may become drastically lower in the future. Whether or not
  this feature is enabled, the metadata is all contained within an isolated
  memory region with high entropy random guard regions around it.

The following integer configuration options are available:

* `CONFIG_SLAB_QUARANTINE_RANDOM_LENGTH`: `1` (default) to control the number
  of slots in the random array used to randomize reuse for small memory
  allocations. This sets the length for the largest size class (either 16kiB
  or 128kiB based on `CONFIG_EXTENDED_SIZE_CLASSES`) and the quarantine length
  for smaller size classes is scaled to match the total memory of the
  quarantined allocations (1 becomes 1024 for 16 byte allocations with 16kiB
  as the largest size class, or 8192 with 128kiB as the largest).
* `CONFIG_SLAB_QUARANTINE_QUEUE_LENGTH`: `1` (default) to control the number of
  slots in the queue used to delay reuse for small memory allocations. This
  sets the length for the largest size class (either 16kiB or 128kiB based on
  `CONFIG_EXTENDED_SIZE_CLASSES`) and the quarantine length for smaller size
  classes is scaled to match the total memory of the quarantined allocations (1
  becomes 1024 for 16 byte allocations with 16kiB as the largest size class, or
  8192 with 128kiB as the largest).
* `CONFIG_GUARD_SLABS_INTERVAL`: `1` (default) to control the number of slabs
  before a slab is skipped and left as an unused memory protected guard slab.
  The default of `1` leaves a guard slab between every slab. This feature does
  not have a *direct* performance cost, but it makes the address space usage
  sparser which can indirectly hurt performance. The kernel also needs to track
  a lot more memory mappings, which uses a bit of extra memory and slows down
  memory mapping and memory protection changes in the process. The kernel uses
  O(log n) algorithms for this and system calls are already fairly slow anyway,
  so having many extra mappings doesn't usually add up to a significant cost.
* `CONFIG_GUARD_SIZE_DIVISOR`: `2` (default) to control the maximum size of the
  guard regions placed on both sides of large memory allocations, relative to
  the usable size of the memory allocation.
* `CONFIG_REGION_QUARANTINE_RANDOM_LENGTH`: `256` (default) to control the
  number of slots in the random array used to randomize region reuse for large
  memory allocations.
* `CONFIG_REGION_QUARANTINE_QUEUE_LENGTH`: `1024` (default) to control the
  number of slots in the queue used to delay region reuse for large memory
  allocations.
* `CONFIG_REGION_QUARANTINE_SKIP_THRESHOLD`: `33554432` (default) to control
  the size threshold where large allocations will not be quarantined.
* `CONFIG_FREE_SLABS_QUARANTINE_RANDOM_LENGTH`: `32` (default) to control the
  number of slots in the random array used to randomize free slab reuse.
* `CONFIG_CLASS_REGION_SIZE`: `34359738368` (default) to control the size of
  the size class regions.
* `CONFIG_N_ARENA`: `4` (default) to control the number of arenas
* `CONFIG_STATS`: `false` (default) to control whether stats on allocation /
  deallocation count and active allocations are tracked. See the [section on
  stats](#stats) for more details.
* `CONFIG_EXTENDED_SIZE_CLASSES`: `true` (default) to control whether small
  size class go up to 128kiB instead of the minimum requirement for avoiding
  memory waste of 16kiB. The option to extend it even further will be offered
  in the future when better support for larger slab allocations is added. See
  the [section on size classes](#size-classes) below for details.
* `CONFIG_LARGE_SIZE_CLASSES`: `true` (default) to control whether large
  allocations use the slab allocation size class scheme instead of page size
  granularity. See the [section on size classes](#size-classes) below for
  details.

There will be more control over enabled features in the future along with
control over fairly arbitrarily chosen values like the size of empty slab
caches (making them smaller improves security and reduces memory usage while
larger caches can substantially improves performance).

## Core design

The core design of the allocator is very simple / minimalist. The allocator is
exclusive to 64-bit platforms in order to take full advantage of the abundant
address space without being constrained by needing to keep the design
compatible with 32-bit.

The mutable allocator state is entirely located within a dedicated metadata
region, and the allocator is designed around this approach for both small
(slab) allocations and large allocations. This provides reliable, deterministic
protections against invalid free including double frees, and protects metadata
from attackers. Traditional allocator exploitation techniques do not work with
the hardened\_malloc implementation.

Small allocations are always located in a large memory region reserved for slab
allocations. On free, it can be determined that an allocation is one of the
small size classes from the address range. If arenas are enabled, the arena is
also determined from the address range as each arena has a dedicated sub-region
in the slab allocation region. Arenas provide totally independent slab
allocators with their own allocator state and no coordination between them.
Once the base region is determined (simply the slab allocation region as a
whole without any arenas enabled), the size class is determined from the
address range too, since it's divided up into a sub-region for each size class.
There's a top level slab allocation region, divided up into arenas, with each
of those divided up into size class regions. The size class regions each have a
random base within a large guard region. Once the size class is determined, the
slab size is known, and the index of the slab is calculated and used to obtain
the slab metadata for the slab from the slab metadata array. Finally, the index
of the slot within the slab provides the index of the bit tracking the slot in
the bitmap. Every slab allocation slot has a dedicated bit in a bitmap tracking
whether it's free, along with a separate bitmap for tracking allocations in the
quarantine. The slab metadata entries in the array have intrusive lists
threaded through them to track partial slabs (partially filled, and these are
the first choice for allocation), empty slabs (limited amount of cached free
memory) and free slabs (purged / memory protected).

Large allocations are tracked via a global hash table mapping their address to
their size and random guard size. They're simply memory mappings and get mapped
on allocation and then unmapped on free. Large allocations are the only dynamic
memory mappings made by the allocator, since the address space for allocator
state (including both small / large allocation metadata) and slab allocations
is statically reserved.

This allocator is aimed at production usage, not aiding with finding and fixing
memory corruption bugs for software development. It does find many latent bugs
but won't include features like the option of generating and storing stack
traces for each allocation to include the allocation site in related error
messages. The design choices are based around minimizing overhead and
maximizing security which often leads to different decisions than a tool
attempting to find bugs. For example, it uses zero-based sanitization on free
and doesn't minimize slack space from size class rounding between the end of an
allocation and the canary / guard region. Zero-based filling has the least
chance of uncovering latent bugs, but also the best chance of mitigating
vulnerabilities. The canary feature is primarily meant to act as padding
absorbing small overflows to render them harmless, so slack space is helpful
rather than harmful despite not detecting the corruption on free. The canary
needs detection on free in order to have any hope of stopping other kinds of
issues like a sequential overflow, which is why it's included.  It's assumed
that an attacker can figure out the allocator is in use so the focus is
explicitly not on detecting bugs that are impossible to exploit with it in use
like an 8 byte overflow. The design choices would be different if performance
was a bit less important and if a core goal was finding latent bugs.

## Security properties

* Fully out-of-line metadata/state with protection from corruption
    * Address space for allocator state is entirely reserved during
      initialization and never reused for allocations or anything else
    * State within global variables is entirely read-only after initialization
      with pointers to the isolated allocator state so leaking the address of
      the library doesn't leak the address of writable state
    * Allocator state is located within a dedicated region with high entropy
      randomly sized guard regions around it
    * Protection via Memory Protection Keys (MPK) on x86\_64 (disabled by
      default due to low benefit-cost ratio on top of baseline protections)
    * [future] Protection via MTE on ARMv8.5+
* Deterministic detection of any invalid free (unallocated, unaligned, etc.)
    * Validation of the size passed for C++14 sized deallocation by `delete`
      even for code compiled with earlier standards (detects type confusion if
      the size is different) and by various containers using the allocator API
      directly
* Isolated memory region for slab allocations
    * Top-level isolated regions for each arena
    * Divided up into isolated inner regions for each size class
        * High entropy random base for each size class region
        * No deterministic / low entropy offsets between allocations with
          different size classes
    * Metadata is completely outside the slab allocation region
        * No references to metadata within the slab allocation region
        * No deterministic / low entropy offsets to metadata
    * Entire slab region starts out non-readable and non-writable
    * Slabs beyond the cache limit are purged and become non-readable and
      non-writable memory again
        * Placed into a queue for reuse in FIFO order to maximize the time
          spent memory protected
        * Randomized array is used to add a random delay for reuse
* Fine-grained randomization within memory regions
    * Randomly sized guard regions for large allocations
    * Random slot selection within slabs
    * Randomized delayed free for small and large allocations along with slabs
      themselves
    * [in-progress] Randomized choice of slabs
    * [in-progress] Randomized allocation of slabs
* Slab allocations are zeroed on free
* Detection of write-after-free for slab allocations by verifying zero filling
  is intact at allocation time
* Delayed free via a combination of FIFO and randomization for slab allocations
* Large allocations are purged and memory protected on free with the memory
  mapping kept reserved in a quarantine to detect use-after-free
    * The quarantine is primarily based on a FIFO ring buffer, with the oldest
      mapping in the quarantine being unmapped to make room for the most
      recently freed mapping
    * Another layer of the quarantine swaps with a random slot in an array to
      randomize the number of large deallocations required to push mappings out
      of the quarantine
* Memory in fresh allocations is consistently zeroed due to it either being
  fresh pages or zeroed on free after previous usage
* Random canaries placed after each slab allocation to *absorb*
  and then later detect overflows/underflows
    * High entropy per-slab random values
    * Leading byte is zeroed to contain C string overflows
* Possible slab locations are skipped and remain memory protected, leaving slab
  size class regions interspersed with guard pages
* Zero size allocations are a dedicated size class with the entire region
  remaining non-readable and non-writable
* Extension for retrieving the size of allocations with fallback to a sentinel
  for pointers not managed by the allocator [in-progress, full implementation
  needs to be ported from the previous OpenBSD malloc-based allocator]
    * Can also return accurate values for pointers *within* small allocations
    * The same applies to pointers within the first page of large allocations,
      otherwise it currently has to return a sentinel
* No alignment tricks interfering with ASLR like jemalloc, PartitionAlloc, etc.
* No usage of the legacy brk heap
* Aggressive sanity checks
    * Errors other than ENOMEM from mmap, munmap, mprotect and mremap treated
      as fatal, which can help to detect memory management gone wrong elsewhere
      in the process.
* Memory tagging for slab allocations via MTE on ARMv8.5+
    * random memory tags as the baseline, providing probabilistic protection
      against various forms of memory corruption
    * dedicated tag for free slots, set on free, for deterministic protection
      against accessing freed memory
    * guarantee distinct tags for adjacent memory allocations by incrementing
      past matching values for deterministic detection of linear overflows
    * [future] store previous random tag and increment it to get the next tag
      for that slot to provide deterministic use-after-free detection through
      multiple cycles of memory reuse

## Randomness

The current implementation of random number generation for randomization-based
mitigations is based on generating a keystream from a stream cipher (ChaCha8)
in small chunks. Separate CSPRNGs are used for each small size class in each
arena, large allocations and initialization in order to fit into the
fine-grained locking model without needing to waste memory per thread by
having the CSPRNG state in Thread Local Storage. Similarly, it's protected via
the same approach taken for the rest of the metadata. The stream cipher is
regularly reseeded from the OS to provide backtracking and prediction
resistance with a negligible cost. The reseed interval simply needs to be
adjusted to the point that it stops registering as having any significant
performance impact. The performance impact on recent Linux kernels is
primarily from the high cost of system calls and locking since the
implementation is quite efficient (ChaCha20), especially for just generating
the key and nonce for another stream cipher (ChaCha8).

ChaCha8 is a great fit because it's extremely fast across platforms without
relying on hardware support or complex platform-specific code. The security
margins of ChaCha20 would be completely overkill for the use case. Using
ChaCha8 avoids needing to resort to a non-cryptographically secure PRNG or
something without a lot of scrutiny. The current implementation is simply the
reference implementation of ChaCha8 converted into a pure keystream by ripping
out the XOR of the message into the keystream.

The random range generation functions are a highly optimized implementation
too. Traditional uniform random number generation within a range is very high
overhead and can easily dwarf the cost of an efficient CSPRNG.

## Size classes

The zero byte size class is a special case of the smallest regular size class.
It's allocated in a dedicated region like other size classes but with the slabs
never being made readable and writable so the only memory usage is for the slab
metadata.

The choice of size classes for slab allocation is the same as jemalloc, which
is a careful balance between minimizing internal and external fragmentation. If
there are more size classes, more memory is wasted on free slots available only
to allocation requests of those sizes (external fragmentation). If there are
fewer size classes, the spacing between them is larger and more memory is
wasted due to rounding up to the size classes (internal fragmentation). There
are 4 special size classes for the smallest sizes (16, 32, 48, 64) that are
simply spaced out by the minimum spacing (16). Afterwards, there are four size
classes for every power of two spacing which results in bounding the internal
fragmentation below 20% for each size class. This also means there are 4 size
classes for each doubling in size.

The slot counts tied to the size classes are specific to this allocator rather
than being taken from jemalloc. Slabs are always a span of pages so the slot
count needs to be tuned to minimize waste due to rounding to the page size. For
now, this allocator is set up only for 4096 byte pages as a small page size is
desirable for finer-grained memory protection and randomization. It could be
ported to larger page sizes in the future. The current slot counts are only a
preliminary set of values.

| size class | worst case internal fragmentation | slab slots | slab size | internal fragmentation for slabs |
| - | - | - | - | - |
| 16 | 93.75% | 256 | 4096 | 0.0% |
| 32 | 46.88% | 128 | 4096 | 0.0% |
| 48 | 31.25% | 85 | 4096 | 0.390625% |
| 64 | 23.44% | 64 | 4096 | 0.0% |
| 80 | 18.75% | 51 | 4096 | 0.390625% |
| 96 | 15.62% | 42 | 4096 | 1.5625% |
| 112 | 13.39% | 36 | 4096 | 1.5625% |
| 128 | 11.72% | 64 | 8192 | 0.0% |
| 160 | 19.38% | 51 | 8192 | 0.390625% |
| 192 | 16.15% | 64 | 12288 | 0.0% |
| 224 | 13.84% | 54 | 12288 | 1.5625% |
| 256 | 12.11% | 64 | 16384 | 0.0% |
| 320 | 19.69% | 64 | 20480 | 0.0% |
| 384 | 16.41% | 64 | 24576 | 0.0% |
| 448 | 14.06% | 64 | 28672 | 0.0% |
| 512 | 12.3% | 64 | 32768 | 0.0% |
| 640 | 19.84% | 64 | 40960 | 0.0% |
| 768 | 16.54% | 64 | 49152 | 0.0% |
| 896 | 14.17% | 64 | 57344 | 0.0% |
| 1024 | 12.4% | 64 | 65536 | 0.0% |
| 1280 | 19.92% | 16 | 20480 | 0.0% |
| 1536 | 16.6% | 16 | 24576 | 0.0% |
| 1792 | 14.23% | 16 | 28672 | 0.0% |
| 2048 | 12.45% | 16 | 32768 | 0.0% |
| 2560 | 19.96% | 8 | 20480 | 0.0% |
| 3072 | 16.63% | 8 | 24576 | 0.0% |
| 3584 | 14.26% | 8 | 28672 | 0.0% |
| 4096 | 12.48% | 8 | 32768 | 0.0% |
| 5120 | 19.98% | 8 | 40960 | 0.0% |
| 6144 | 16.65% | 8 | 49152 | 0.0% |
| 7168 | 14.27% | 8 | 57344 | 0.0% |
| 8192 | 12.49% | 8 | 65536 | 0.0% |
| 10240 | 19.99% | 6 | 61440 | 0.0% |
| 12288 | 16.66% | 5 | 61440 | 0.0% |
| 14336 | 14.28% | 4 | 57344 | 0.0% |
| 16384 | 12.49% | 4 | 65536 | 0.0% |

The slab allocation size classes end at 16384 since that's the final size for
2048 byte spacing and the next spacing class matches the page size of 4096
bytes on the target platforms. This is the minimum set of small size classes
required to avoid substantial waste from rounding.

The `CONFIG_EXTENDED_SIZE_CLASSES` option extends the size classes up to
131072, with a final spacing class of 16384. This offers improved performance
compared to the minimum set of size classes. The security story is complicated,
since the slab allocation has both advantages like size class isolation
completely avoiding reuse of any of the address space for any other size
classes or other data. It also has disadvantages like caching a small number of
empty slabs and deterministic guard sizes. The cache will be configurable in
the future, making it possible to disable slab caching for the largest slab
allocation sizes, to force unmapping them immediately and putting them in the
slab quarantine, which eliminates most of the security disadvantage at the
expense of also giving up most of the performance advantage, but while
retaining the isolation.

| size class | worst case internal fragmentation | slab slots | slab size | internal fragmentation for slabs |
| - | - | - | - | - |
| 20480 | 20.0% | 1 | 20480 | 0.0% |
| 24576 | 16.66% | 1 | 24576 | 0.0% |
| 28672 | 14.28% | 1 | 28672 | 0.0% |
| 32768 | 12.5% | 1 | 32768 | 0.0% |
| 40960 | 20.0% | 1 | 40960 | 0.0% |
| 49152 | 16.66% | 1 | 49152 | 0.0% |
| 57344 | 14.28% | 1 | 57344 | 0.0% |
| 65536 | 12.5% | 1 | 65536 | 0.0% |
| 81920 | 20.0% | 1 | 81920 | 0.0% |
| 98304 | 16.67% | 1 | 98304 | 0.0% |
| 114688 | 14.28% | 1 | 114688 | 0.0% |
| 131072 | 12.5% | 1 | 131072 | 0.0% |

The `CONFIG_LARGE_SIZE_CLASSES` option controls whether large allocations use
the same size class scheme providing 4 size classes for every doubling of size.
It increases virtual memory consumption but drastically improves performance
where realloc is used without proper growth factors, which is fairly common and
destroys performance in some commonly used programs. If large size classes are
disabled, the granularity is instead the page size, which is currently always
4096 bytes on supported platforms.

## Scalability

### Small (slab) allocations

As a baseline form of fine-grained locking, the slab allocator has entirely
separate allocators for each size class. Each size class has a dedicated lock,
CSPRNG and other state.

The slab allocator's scalability primarily comes from dividing up the slab
allocation region into independent arenas assigned to threads. The arenas are
just entirely separate slab allocators with their own sub-regions for each size
class. Using 4 arenas reserves a region 4 times as large and the relevant slab
allocator metadata is determined based on address, as part of the same approach
to finding the per-size-class metadata. The part that's still open to different
design choices is how arenas are assigned to threads. One approach is
statically assigning arenas via round-robin like the standard jemalloc
implementation, or statically assigning to a random arena which is essentially
the current implementation. Another option is dynamic load balancing via a
heuristic like `sched_getcpu` for per-CPU arenas, which would offer better
performance than randomly choosing an arena each time while being more
predictable for an attacker. There are actually some security benefits from
this assignment being completely static, since it isolates threads from each
other. Static assignment can also reduce memory usage since threads may have
varying usage of size classes.

When there's substantial allocation or deallocation pressure, the allocator
does end up calling into the kernel to purge / protect unused slabs by
replacing them with fresh `PROT_NONE` regions along with unprotecting slabs
when partially filled and cached empty slabs are depleted. There will be
configuration over the amount of cached empty slabs, but it's not entirely a
performance vs. memory trade-off since memory protecting unused slabs is a nice
opportunistic boost to security. However, it's not really part of the core
security model or features so it's quite reasonable to use much larger empty
slab caches when the memory usage is acceptable. It would also be reasonable to
attempt to use heuristics for dynamically tuning the size, but there's not a
great one size fits all approach so it isn't currently part of this allocator
implementation.

#### Thread caching (or lack thereof)

Thread caches are a commonly implemented optimization in modern allocators but
aren't very suitable for a hardened allocator even when implemented via arrays
like jemalloc rather than free lists. They would prevent the allocator from
having perfect knowledge about which memory is free in a way that's both race
free and works with fully out-of-line metadata. It would also interfere with
the quality of fine-grained randomization even with randomization support in
the thread caches. The caches would also end up with much weaker protection
than the dedicated metadata region. Potentially worst of all, it's inherently
incompatible with the important quarantine feature.

The primary benefit from a thread cache is performing batches of allocations
and batches of deallocations to amortize the cost of the synchronization used
by locking. The issue is not contention but rather the cost of synchronization
itself. Performing operations in large batches isn't necessarily a good thing
in terms of reducing contention to improve scalability. Large thread caches
like TCMalloc are a legacy design choice and aren't a good approach for a
modern allocator. In jemalloc, thread caches are fairly small and have a form
of garbage collection to clear them out when they aren't being heavily used.
Since this is a hardened allocator with a bunch of small costs for the security
features, the synchronization is already a smaller percentage of the overall
time compared to a much leaner performance-oriented allocator. These benefits
could be obtained via allocation queues and deallocation queues which would
avoid bypassing the quarantine and wouldn't have as much of an impact on
randomization. However, deallocation queues would also interfere with having
global knowledge about what is free. An allocation queue alone wouldn't have
many drawbacks, but it isn't currently planned even as an optional feature
since it probably wouldn't be enabled by default and isn't worth the added
complexity.

The secondary benefit of thread caches is being able to avoid the underlying
allocator implementation entirely for some allocations and deallocations when
they're mixed together rather than many allocations being done together or many
frees being done together. The value of this depends a lot on the application
and it's entirely unsuitable / incompatible with a hardened allocator since it
bypasses all of the underlying security and would destroy much of the security
value.

### Large allocations

The expectation is that the allocator does not need to perform well for large
allocations, especially in terms of scalability. When the performance for large
allocations isn't good enough, the approach will be to enable more slab
allocation size classes. Doubling the maximum size of slab allocations only
requires adding 4 size classes while keeping internal waste bounded below 20%.

Large allocations are implemented as a wrapper on top of the kernel memory
mapping API. The addresses and sizes are tracked in a global data structure
with a global lock. The current implementation is a hash table and could easily
use fine-grained locking, but it would have little benefit since most of the
locking is in the kernel. Most of the contention will be on the `mmap_sem` lock
for the process in the kernel. Ideally, it could simply map memory when
allocating and unmap memory when freeing. However, this is a hardened allocator
and the security features require extra system calls due to lack of direct
support for this kind of hardening in the kernel. Randomly sized guard regions
are placed around each allocation which requires mapping a `PROT_NONE` region
including the guard regions and then unprotecting the usable area between them.
The quarantine implementation requires clobbering the mapping with a fresh
`PROT_NONE` mapping using `MAP_FIXED` on free to hold onto the region while
it's in the quarantine, until it's eventually unmapped when it's pushed out of
the quarantine. This means there are 2x as many system calls for allocating and
freeing as there would be if the kernel supported these features directly.

## Memory tagging

Random tags are set for all slab allocations when allocated, with 4 excluded values:

1. the reserved `0` tag
2. the previous tag used for the slot
3. the current (or previous) tag used for the slot to the left
4. the current (or previous) tag used for the slot to the right

When a slab allocation is freed, the reserved `0` tag is set for the slot.
Slab allocation slots are cleared before reuse when memory tagging is enabled.

This ensures the following properties:

- Linear overflows are deterministically detected.
- Use-after-free are deterministically detected until the freed slot goes through
  both the random and FIFO quarantines, gets allocated again, goes through both
  quarantines again and then finally gets allocated again for a 2nd time.
- Since the default `0` tag is reserved, untagged pointers can't access slab
  allocations and vice versa.

Slab allocations are done in a statically reserved region for each size class
and all metadata is in a statically reserved region, so interactions between
different uses of the same address space is not applicable.

Large allocations beyond the largest slab allocation size class (128k by
default) are guaranteed to have randomly sized guard regions to the left and
right. Random and FIFO address space quarantines provide use-after-free
detection. We need to test whether the cost of random tags is acceptable to enabled them by default,
since they would be useful for:

- probabilistic detection of overflows
- probabilistic detection of use-after-free once the address space is
  out of the quarantine and reused for another allocation
- deterministic detection of use-after-free for reuse by another allocator.

When memory tagging is enabled, checking for write-after-free at allocation
time and checking canaries are both disabled. Canaries will be more thoroughly
disabled when using memory tagging in the future, but Android currently has
[very dynamic memory tagging support](https://source.android.com/docs/security/test/memory-safety/arm-mte)
where it can be disabled at any time which creates a barrier to optimizing
by disabling redundant features.

## API extensions

The `void free_sized(void *ptr, size_t expected_size)` function exposes the
sized deallocation sanity checks for C. A performance-oriented allocator could
use the same API as an optimization to avoid a potential cache miss from
reading the size from metadata.

The `size_t malloc_object_size(void *ptr)` function returns an *upper bound* on
the accessible size of the relevant object (if any) by querying the malloc
implementation. It's similar to the `__builtin_object_size` intrinsic used by
`_FORTIFY_SOURCE` but via dynamically querying the malloc implementation rather
than determining constant sizes at compile-time. The current implementation is
just a naive placeholder returning much looser upper bounds than the intended
implementation. It's a valid implementation of the API already, but it will
become fully accurate once it's finished. This function is **not** currently
safe to call from signal handlers, but another API will be provided to make
that possible with a compile-time configuration option to avoid the necessary
overhead if the functionality isn't being used (in a way that doesn't change
break API compatibility based on the configuration).

The `size_t malloc_object_size_fast(void *ptr)` is comparable, but avoids
expensive operations like locking or even atomics. It provides significantly
less useful results falling back to higher upper bounds, but is very fast. In
this implementation, it retrieves an upper bound on the size for small memory
allocations based on calculating the size class region. This function is safe
to use from signal handlers already.

## Stats

If stats are enabled, hardened\_malloc keeps tracks allocator statistics in
order to provide implementations of `mallinfo` and `malloc_info`.

On Android, `mallinfo` is used for [mallinfo-based garbage collection
triggering](https://developer.android.com/preview/features#mallinfo) so
hardened\_malloc enables `CONFIG_STATS` by default. The `malloc_info`
implementation on Android is the standard one in Bionic, with the information
provided to Bionic via Android's internal extended `mallinfo` API with support
for arenas and size class bins. This means the `malloc_info` output is fully
compatible, including still having `jemalloc-1` as the version of the data
format to retain compatibility with existing tooling.

On non-Android Linux, `mallinfo` has zeroed fields even with `CONFIG_STATS`
enabled because glibc `mallinfo` is inherently broken. It defines the fields as
`int` instead of `size_t`, resulting in undefined signed overflows. It also
misuses the fields and provides a strange, idiosyncratic set of values rather
than following the SVID/XPG `mallinfo` definition. The `malloc_info` function
is still provided, with a similar format as what Android uses, with tweaks for
hardened\_malloc and the version set to `hardened_malloc-1`. The data format
may be changed in the future.

As an example, consider the following program from the hardened\_malloc tests:

```c
#include <pthread.h>

#include <malloc.h>

__attribute__((optimize(0)))
void leak_memory(void) {
    (void)malloc(1024 * 1024 * 1024);
    (void)malloc(16);
    (void)malloc(32);
    (void)malloc(4096);
}

void *do_work(void *p) {
    leak_memory();
    return NULL;
}

int main(void) {
    pthread_t thread[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&thread[i], NULL, do_work, NULL);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(thread[i], NULL);
    }

    malloc_info(0, stdout);
}
```

This produces the following output when piped through `xmllint --format -`:

```xml
<?xml version="1.0"?>
<malloc version="hardened_malloc-1">
  <heap nr="0">
    <bin nr="2" size="32">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>32</allocated>
    </bin>
    <bin nr="3" size="48">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>48</allocated>
    </bin>
    <bin nr="13" size="320">
      <nmalloc>4</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>20480</slab_allocated>
      <allocated>1280</allocated>
    </bin>
    <bin nr="29" size="5120">
      <nmalloc>2</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>40960</slab_allocated>
      <allocated>10240</allocated>
    </bin>
    <bin nr="45" size="81920">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>81920</slab_allocated>
      <allocated>81920</allocated>
    </bin>
  </heap>
  <heap nr="1">
    <bin nr="2" size="32">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>32</allocated>
    </bin>
    <bin nr="3" size="48">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>48</allocated>
    </bin>
    <bin nr="29" size="5120">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>40960</slab_allocated>
      <allocated>5120</allocated>
    </bin>
  </heap>
  <heap nr="2">
    <bin nr="2" size="32">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>32</allocated>
    </bin>
    <bin nr="3" size="48">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>48</allocated>
    </bin>
    <bin nr="29" size="5120">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>40960</slab_allocated>
      <allocated>5120</allocated>
    </bin>
  </heap>
  <heap nr="3">
    <bin nr="2" size="32">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>32</allocated>
    </bin>
    <bin nr="3" size="48">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>4096</slab_allocated>
      <allocated>48</allocated>
    </bin>
    <bin nr="29" size="5120">
      <nmalloc>1</nmalloc>
      <ndalloc>0</ndalloc>
      <slab_allocated>40960</slab_allocated>
      <allocated>5120</allocated>
    </bin>
  </heap>
  <heap nr="4">
    <allocated_large>4294967296</allocated_large>
  </heap>
</malloc>
```

The heap entries correspond to the arenas. Unlike jemalloc, hardened\_malloc
doesn't handle large allocations within the arenas, so it presents those in the
`malloc_info` statistics as a separate arena dedicated to large allocations.
For example, with 4 arenas enabled, there will be a 5th arena in the statistics
for the large allocations.

The `nmalloc` / `ndalloc` fields are 64-bit integers tracking allocation and
deallocation count. These are defined as wrapping on overflow, per the jemalloc
implementation.

See the [section on size classes](#size-classes) to map the size class bin
number to the corresponding size class. The bin index begins at 0, mapping to
the 0 byte size class, followed by 1 for the 16 bytes, 2 for 32 bytes, etc. and
large allocations are treated as one group.

When stats aren't enabled, the `malloc_info` output will be an empty `malloc`
element.

## System calls

This is intended to aid with creating system call whitelists via seccomp-bpf
and will change over time.

System calls used by all build configurations:

* `futex(uaddr, FUTEX_WAIT_PRIVATE, val, NULL)` (via `pthread_mutex_lock`)
* `futex(uaddr, FUTEX_WAKE_PRIVATE, val)` (via `pthread_mutex_unlock`)
* `getrandom(buf, buflen, 0)` (to seed and regularly reseed the CSPRNG)
* `mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)`
* `mmap(ptr, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0)`
* `mprotect(ptr, size, PROT_READ)`
* `mprotect(ptr, size, PROT_READ|PROT_WRITE)`
* `mremap(old, old_size, new_size, 0)`
* `mremap(old, old_size, new_size, MREMAP_MAYMOVE|MREMAP_FIXED, new)`
* `munmap`
* `write(STDERR_FILENO, buf, len)` (before aborting due to memory corruption)
* `madvise(ptr, size, MADV_DONTNEED)`

The main distinction from a typical malloc implementation is the use of
getrandom. A common compatibility issue is that existing system call whitelists
often omit getrandom partly due to older code using the legacy `/dev/urandom`
interface along with the overall lack of security features in mainstream libc
implementations.

Additional system calls when `CONFIG_SEAL_METADATA=true` is set:

* `pkey_alloc`
* `pkey_mprotect` instead of `mprotect` with an additional `pkey` parameter,
  but otherwise the same (regular `mprotect` is never called)

Additional system calls for Android builds with `LABEL_MEMORY`:

* `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, size, name)`
