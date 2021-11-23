#include <bits/functexcept.h>
#include <new>

#include "h_malloc.h"
#include "util.h"

COLD static void *handle_out_of_memory(size_t size, bool nothrow) {
    void *ptr = nullptr;

    do {
        std::new_handler handler = std::get_new_handler();
        if (handler == nullptr) {
            break;
        }

        try {
            handler();
        } catch (const std::bad_alloc &) {
            break;
        }

        ptr = h_malloc(size);
    } while (ptr == nullptr);

    if (ptr == nullptr && !nothrow) {
        std::__throw_bad_alloc();
    }
    return ptr;
}

static inline void *new_impl(size_t size, bool nothrow) {
    void *ptr = h_malloc(size);
    if (likely(ptr != nullptr)) {
        return ptr;
    }
    return handle_out_of_memory(size, nothrow);
}

EXPORT void *operator new(size_t size) {
    return new_impl(size, false);
}

EXPORT void *operator new[](size_t size) {
    return new_impl(size, false);
}

EXPORT void *operator new(size_t size, const std::nothrow_t &) noexcept {
    return new_impl(size, true);
}

EXPORT void *operator new[](size_t size, const std::nothrow_t &) noexcept {
    return new_impl(size, true);
}

EXPORT void operator delete(void *ptr) noexcept {
    h_free(ptr);
}

EXPORT void operator delete[](void *ptr) noexcept {
    h_free(ptr);
}

EXPORT void operator delete(void *ptr, const std::nothrow_t &) noexcept {
    h_free(ptr);
}

EXPORT void operator delete[](void *ptr, const std::nothrow_t &) noexcept {
    h_free(ptr);
}

EXPORT void operator delete(void *ptr, size_t size) noexcept {
    h_free_sized(ptr, size);
}

EXPORT void operator delete[](void *ptr, size_t size) noexcept {
    h_free_sized(ptr, size);
}

COLD static void *handle_out_of_memory(size_t size, size_t alignment, bool nothrow) {
    void *ptr = nullptr;

    do {
        std::new_handler handler = std::get_new_handler();
        if (handler == nullptr) {
            break;
        }

        try {
            handler();
        } catch (const std::bad_alloc &) {
            break;
        }

        ptr = h_aligned_alloc(alignment, size);
    } while (ptr == nullptr);

    if (ptr == nullptr && !nothrow) {
        std::__throw_bad_alloc();
    }
    return ptr;
}

static inline void *new_impl(size_t size, size_t alignment, bool nothrow) {
    void *ptr = h_aligned_alloc(alignment, size);
    if (likely(ptr != nullptr)) {
        return ptr;
    }
    return handle_out_of_memory(size, alignment, nothrow);
}

EXPORT void *operator new(size_t size, std::align_val_t alignment) {
    return new_impl(size, static_cast<size_t>(alignment), false);
}

EXPORT void *operator new[](size_t size, std::align_val_t alignment) {
    return new_impl(size, static_cast<size_t>(alignment), false);
}

EXPORT void *operator new(size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept {
    return new_impl(size, static_cast<size_t>(alignment), true);
}

EXPORT void *operator new[](size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept {
    return new_impl(size, static_cast<size_t>(alignment), true);
}

EXPORT void operator delete(void *ptr, std::align_val_t) noexcept {
    h_free(ptr);
}

EXPORT void operator delete[](void *ptr, std::align_val_t) noexcept {
    h_free(ptr);
}

EXPORT void operator delete(void *ptr, std::align_val_t, const std::nothrow_t &) noexcept {
    h_free(ptr);
}

EXPORT void operator delete[](void *ptr, std::align_val_t, const std::nothrow_t &) noexcept {
    h_free(ptr);
}

EXPORT void operator delete(void *ptr, size_t size, std::align_val_t) noexcept {
    h_free_sized(ptr, size);
}

EXPORT void operator delete[](void *ptr, size_t size, std::align_val_t) noexcept {
    h_free_sized(ptr, size);
}
