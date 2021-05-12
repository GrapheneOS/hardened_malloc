Very important and should be an easy sell:

* improved robustness for high vma count on high memory machines
* much higher `vm.max_map_count` by default
* work on improving performance and resource usage with high vma count
* add a way to disable the brk heap and have mmap grow upwards like it did in
  the past (preserving the same high base entropy)

Somewhat important and an easy sell:

* alternative to `RLIMIT_AS` for accountable mappings only
    * memory control groups are sometimes a better option but there are still
      users of `RLIMIT_AS` that are problematic for mitigations or simply fast
      garbage collector implementations, etc. mapping lots of `PROT_NONE` memory
* mremap flag to disable unmapping the source mapping
    * also needed by jemalloc for different reasons
    * not needed if the kernel gets first class support for arbitrarily sized
      guard pages and a virtual memory quarantine feature
    * `MREMAP_DONTUNMAP` is now available but doesn't support expanding the
      mapping which may be an issue due to VMA merging being unreliable

Fairly infeasible to land but could reduce overhead and extend coverage of
security features to other code directly using mmap:

* first class support for arbitrarily sized guard pages for mmap and mremap to
  eliminate half of the resulting VMAs and reduce 2 system calls to 1
    * not usable if it doesn't support mremap (shrink, grow, grow via move)
    * not usable if the guard page size is static
    * should support changing guard size for mremap growth via move
    * must be possible to set it up from the process
* virtual memory quarantine
    * must be possible to set it up from the process
* first-class support for aligned mappings with mmap and ideally mremap
    * not usable unless guard page support is provided and of course it has to
      work with this too
