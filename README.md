This project currently aims to support Android, musl and glibc. It may support
other non-Linux operating systems in the future. For Android and musl, there
will be custom integration and other hardening features. The glibc support will
be limited to replacing the malloc implementation because musl is a much more
robust and cleaner base to build on and can cover the same use cases.

Debian stable determines the most ancient set of supported dependencies:

* glibc 2.24
* Linux 4.9
* Clang 3.8 or GCC 6.3

However, using more recent releases is highly recommended. Older versions of
the dependencies may be compatible at the moment but are not tested and will
explicitly not be supported.

For external malloc replacement with musl, musl 1.1.20 is required. However,
there will be custom integration offering better performance in the future
along with other hardening for the C standard library implementation.

Major releases of Android will be supported until tags stop being pushed to
the Android Open Source Project (AOSP). Google supports each major release
with security patches for 3 years, but tagged releases of the Android Open
Source Project are more than just security patches and are no longer pushed
once no officially supported devices are using them anymore. For example, at
the time of writing (September 2018), AOSP only has tagged releases for 8.1
(Nexus 5X, Nexus 5X, Pixel C) and 9.0 (Pixel, Pixel XL, Pixel 2, Pixel 2 XL).
There are ongoing security patches for 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0, 8.1
and 9.0 but only the active AOSP branches (8.1 and 9.0) are supported by this
project and it doesn't make much sense to use much older releases with far
less privacy and security hardening.

# Testing

The `preload.sh` script can be used for testing with dynamically linked
executables using glibc or musl:

    ./preload.sh krita --new-image RGBA,U8,500,500

It can be necessary to substantially increase the `vm.max_map_count` sysctl to
accomodate the large number of mappings caused by guard slabs and large
allocation guard regions. There will be a configuration option in `config.h`
for tuning the proportion of slabs to guard slabs too, since the default 1:1
proportion makes the address space quite sparse.

It can offer slightly better performance when integrated into the C standard
library and there are other opportunities for similar hardening within C
standard library and dynamic linker implementations. For example, a library
region can be implemented to offer similar isolation for dynamic libraries as
this allocator offers across different size classes. The intention is that this
will be offered as part of hardened variants of the Bionic and musl C standard
libraries.

# Configuration

You can set some configuration options at compile-time via arguments to the
make command as follows:

    make CONFIG_EXAMPLE=false

The available configuration options are the following:

* `CONFIG_CXX_ALLOCATOR`: `true` (default) or `false` to control whether the
  C++ allocator is replaced

Compile-time configuration is available in the `config.h` file for controlling
the balance between security and performance / memory usage. By default, all
the optional security features are enabled. Options are only provided for the
features with a significant performance or memory usage cost.

```
#define WRITE_AFTER_FREE_CHECK true
#define SLOT_RANDOMIZE true
#define ZERO_ON_FREE true
#define SLAB_CANARY true
#define GUARD_SLABS_INTERVAL 1
#define GUARD_SIZE_DIVISOR 2
```

There will be more control over enabled features in the future along with
control over fairly arbitrarily chosen values like the size of empty slab
caches (making them smaller improves security), the maximum size of guard
regions for large allocations and the proportion of slabs to guard slabs.

# Basic design

The current design is very simple and will become a bit more sophisticated as
the basic features are completed and the implementation is hardened and
optimized. The allocator is exclusive to 64-bit platforms in order to take full
advantage of the abundant address space without being constrained by needing to
keep the design compatible with 32-bit.

Small allocations are always located in a large memory region reserved for slab
allocations. It can be determined that an allocation is one of the small size
classes from the address range. Each small size class has a separate reserved
region within the larger region, and the size of a small allocation can simply
be determined from the range. Each small size class has a separate out-of-line
metadata array outside of the overall allocation region, with the index of the
metadata struct within the array mapping to the index of the slab within the
dedicated size class region. Slabs are a multiple of the page size and are
page aligned. The entire small size class region starts out memory protected
and becomes readable / writable as it gets allocated, with idle slabs beyond
the cache limit having their pages dropped and the memory protected again.

Large allocations are tracked via a global hash table mapping their address to
their size and guard size. They're simply memory mappings and get mapped on
allocation and then unmapped on free.

# Security properties

* Fully out-of-line metadata
* Deterministic detection of any invalid free (unallocated, unaligned, etc.)
* Isolated memory region for slab allocations
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
* Fine-grained randomization within memory regions
    * Randomly sized guard regions for large allocations
    * Random slot selection within slabs
    * [in-progress] Randomized delayed free for slab allocations
    * [in-progress] Randomized allocation of slabs
    * [more randomization coming as the implementation is matured]
* Slab allocations are zeroed on free and large allocations are unmapped
* Detection of write-after-free by verifying zero filling is intact
* Memory in fresh allocations is consistently zeroed due to it either being
  fresh pages or zeroed on free after previous usage
* [in-progress] Delayed free via a combination of FIFO and randomization for
  slab allocations
* Random canaries placed after each slab allocation to *absorb*
  and then later detect overflows/underflows
    * High entropy per-slab random values
    * Leading byte is zeroed to contain C string overflows
    * [in-progress] Mangled into a unique value per slab slot (although not
      with a strong keyed hash due to performance limitations)
* Possible slab locations are skipped and remain memory protected, leaving slab
  size class regions interspersed with guard pages
* Zero size allocations are memory protected
* Protected allocator metadata
    * Address space for metadata is never used for allocations and vice versa
    * [implementing stronger protection is in-progress]
* Extension for retrieving the size of allocations with fallback
  to a sentinel for pointers not managed by the allocator
    * Can also return accurate values for pointers *within* small allocations
    * The same applies to pointers within the first page of large allocations,
      otherwise it currently has to return a sentinel
* No alignment tricks interfering with ASLR like jemalloc, PartitionAlloc, etc.
* No usage of the legacy brk heap
* Aggressive sanity checks
    * Errors other than ENOMEM from mmap, munmap, mprotect and mremap treated
      as fatal, which can help to detect memory management gone wrong elsewhere
      in the process.

# Randomness

The current implementation of random number generation for randomization-based
mitigations is based on generating a keystream from a stream cipher (ChaCha8)
in small chunks. A separate CSPRNG is used for each small size class, large
allocations, etc. in order to fit into the existing fine-grained locking model
without needing to waste memory per thread by having the CSPRNG state in Thread
Local Storage. Similarly, it's protected via the same approach taken for the
rest of the metadata. The stream cipher is regularly reseeded from the OS to
provide backtracking and prediction resistance with a negligible cost. The
reseed interval simply needs to be adjusted to the point that it stops
registering as having any significant performance impact. The performance
impact on recent Linux kernels is primarily from the high cost of system calls
and locking since the implementation is quite efficient (ChaCha20), especially
for just generating the key and nonce for another stream cipher (ChaCha8).

ChaCha8 is a great fit because it's extremely fast across platforms without
relying on hardware support or complex platform-specific code. The security
margins of ChaCha20 would be completely overkill for the use case. Using
ChaCha8 avoids needing to resort to a non-cryptographically secure PRNG or
something without a lot of scrunity. The current implementation is simply the
reference implementation of ChaCha8 converted into a pure keystream by ripping
out the XOR of the message into the keystream.

The random range generation functions are a highly optimized implementation
too. Traditional uniform random number generation within a range is very high
overhead and can easily dwarf the cost of an efficient CSPRNG.

# Size classes

The zero byte size class is a special case of the smallest regular size class. It's allocated in a
separate region with the memory left non-readable and non-writable.

The slab slot count for each size class is not yet finely tuned beyond choosing values avoiding
internal fragmentation for slabs (i.e. avoiding wasted space due to page size rounding).

The choice of size classes is the same as jemalloc, but with a much different approach to the
slabs containing them:

> size classes are multiples of the quantum [16], spaced such that there are four size classes for
> each doubling in size, which limits internal fragmentation to approximately 20% for all but the
> smallest size classes

| size class | worst case internal fragmentation | slab slots | slab size | worst case internal fragmentation for slabs |
| - | - | - | - | - |
| 16 | 100% | 256 | 4096 | 0.0% |
| 32 | 46.875% | 128 | 4096 | 0.0% |
| 48 | 31.25% | 85 | 4096 | 0.390625% |
| 64 | 23.4375% | 64 | 4096 | 0.0% |
| 80 | 18.75% | 51 | 4096 | 0.390625% |
| 96 | 15.625% | 42 | 4096 | 1.5625% |
| 112 | 13.392857142857139% | 36 | 4096 | 1.5625% |
| 128 | 11.71875% | 64 | 8192 | 0.0% |
| 160 | 19.375% | 51 | 8192 | 0.390625% |
| 192 | 16.145833333333343% | 64 | 12288 | 0.0% |
| 224 | 13.839285714285708% | 54 | 12288 | 1.5625% |
| 256 | 12.109375% | 64 | 16384 | 0.0% |
| 320 | 19.6875% | 64 | 20480 | 0.0% |
| 384 | 16.40625% | 64 | 24576 | 0.0% |
| 448 | 14.0625% | 64 | 28672 | 0.0% |
| 512 | 12.3046875% | 64 | 32768 | 0.0% |
| 640 | 19.84375% | 64 | 40960 | 0.0% |
| 768 | 16.536458333333343% | 64 | 49152 | 0.0% |
| 896 | 14.174107142857139% | 64 | 57344 | 0.0% |
| 1024 | 12.40234375% | 64 | 65536 | 0.0% |
| 1280 | 19.921875% | 16 | 20480 | 0.0% |
| 1536 | 16.6015625% | 16 | 24576 | 0.0% |
| 1792 | 14.229910714285708% | 16 | 28672 | 0.0% |
| 2048 | 12.451171875% | 16 | 32768 | 0.0% |
| 2560 | 19.9609375% | 8 | 20480 | 0.0% |
| 3072 | 16.634114583333343% | 8 | 24576 | 0.0% |
| 3584 | 14.2578125% | 8 | 28672 | 0.0% |
| 4096 | 12.4755859375% | 8 | 32768 | 0.0% |
| 5120 | 19.98046875% | 8 | 40960 | 0.0% |
| 6144 | 16.650390625% | 8 | 49152 | 0.0% |
| 7168 | 14.271763392857139% | 8 | 57344 | 0.0% |
| 8192 | 12.48779296875% | 8 | 65536 | 0.0% |
| 10240 | 19.990234375% | 6 | 61440 | 0.0% |
| 12288 | 16.658528645833343% | 5 | 61440 | 0.0% |
| 14336 | 14.278738839285708% | 4 | 57344 | 0.0% |
| 16384 | 12.493896484375% | 4 | 65536 | 0.0% |
