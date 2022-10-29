#include <dlfcn.h>
#include <map>

#include "cilksan_internal.h"
#include "debug_util.h"
#include "driver.h"
#include "addrmap.h"

struct interpose_substitution {
  const uintptr_t replacement;
  const uintptr_t original;
};

// For a function foo() create a global pair of pointers { wrap_foo, foo } in
// the __DATA,__interpose section.
// As a result all the calls to foo() will be routed to wrap_foo() at runtime.
#define INTERPOSER(func_name) __attribute__((used)) \
const interpose_substitution substitution_##func_name[] \
    __attribute__((section("__DATA, __interpose"))) = { \
    { reinterpret_cast<const uintptr_t>(WRAP(func_name)), \
      reinterpret_cast<const uintptr_t>(func_name) } \
}

# define WRAP(x) wrap_##x
# define WRAPPER_NAME(x) "wrap_"#x
# define INTERCEPTOR_ATTRIBUTE
# define DECLARE_WRAPPER(ret_type, func, ...)

// FIXME: Currently these dynamic interposers are never used, because common
// third-party libraries, such as jemalloc, do not work properly when these
// methods are dynamically interposed.  We therefore rely on Cilksan hooks to
// find allocation routines.

static std::map<uintptr_t, size_t> pages_to_clear;

// // Flag to manage initialization of memory functions.  We need this flag because
// // dlsym uses some of the memory functions we are trying to interpose, which
// // means that calling dlsym directly will lead to infinite recursion and a
// // segfault.  Fortunately, dlsym can make do with memory-allocation functions
// // returning NULL, so we return NULL when we detect this inifinite recursion.
// //
// // This trick seems questionable, but it also seems to be standard practice.
// // It's the same trick used by memusage.c in glibc, and there's little
// // documentation on better tricks.
// static int mem_initialized = 0;

// // Pointers to real memory functions.
// typedef void*(*malloc_t)(size_t);
// static malloc_t real_malloc = NULL;

// typedef void*(*calloc_t)(size_t, size_t);
// static calloc_t real_calloc = NULL;

// typedef void*(*realloc_t)(void*, size_t);
// static realloc_t real_realloc = NULL;

// typedef void(*free_t)(void*);
// static free_t real_free = NULL;

// typedef void*(*mmap_t)(void*, size_t, int, int, int, off_t);
// static mmap_t real_mmap = NULL;

// #if defined(_LARGEFILE64_SOURCE)
// typedef void*(*mmap64_t)(void*, size_t, int, int, int, off64_t);
// static mmap64_t real_mmap64 = NULL;
// #endif // defined(_LARGEFILE64_SOURCE)

// typedef int(*munmap_t)(void*, size_t);
// static munmap_t real_munmap = NULL;

// typedef void*(*mremap_t)(void*, size_t, size_t, int, ...);
// static mremap_t real_mremap = NULL;

// // Helper function to get real implementations of memory functions via dlsym.
// static void initialize_memory_functions() {
//   CheckingRAII nocheck;
//   mem_initialized = -1;

//   real_malloc = (malloc_t)dlsym(RTLD_NEXT, "malloc");
//   if (real_malloc == NULL)
//     goto error_exit;

//   real_calloc = (calloc_t)dlsym(RTLD_NEXT, "calloc");
//   if (real_calloc == NULL)
//     goto error_exit;

//   real_realloc = (realloc_t)dlsym(RTLD_NEXT, "realloc");
//   if (real_realloc == NULL)
//     goto error_exit;

//   real_free = (free_t)dlsym(RTLD_NEXT, "free");
//   if (real_free == NULL)
//     goto error_exit;

//   real_mmap = (mmap_t)dlsym(RTLD_NEXT, "mmap");
//   if (real_mmap == NULL)
//     goto error_exit;

// #if defined(_LARGEFILE64_SOURCE)
//   real_mmap64 = (mmap64_t)dlsym(RTLD_NEXT, "mmap64");
//   if (real_mmap64 == NULL)
//     goto error_exit;
// #endif // defined(_LARGEFILE64_SOURCE)

//   real_munmap = (munmap_t)dlsym(RTLD_NEXT, "munmap");
//   if (real_munmap == NULL)
//     goto error_exit;

// #if __linux__
//   real_mremap = (mremap_t)dlsym(RTLD_NEXT, "mremap");
//   if (real_mremap == NULL)
//     goto error_exit;
// #endif // __linux__

//   mem_initialized = 1;
//   return;

//  error_exit:
//   char *error = dlerror();
//   if (error != NULL) {
//     fputs(error, err_io);
//     fflush(err_io);
//   }
//   abort();
// }

CILKSAN_API void* wrap_malloc(size_t size) {
  // // Don't try to init, since that needs malloc.
  // if (__builtin_expect(real_malloc == NULL, 0)) {
  //   if (-1 == mem_initialized)
  //     return NULL;
  //   initialize_memory_functions();
  // }

  if (!__cilksan_should_check())
    return malloc(size);

  // fprintf(stderr, "[CILKSAN] malloc interposer\n");

  void *addr = malloc(size);
  if (0 == size)
    return addr;

  __cilksan_record_alloc(addr, size);

  return addr;
}

INTERPOSER(malloc);

CILKSAN_API void* wrap_calloc(size_t num, size_t size) {
  // if (__builtin_expect(real_calloc == NULL, 0)) {
  //   if (-1 == mem_initialized)
  //     return NULL;
  //   initialize_memory_functions();
  // }

  if (!CILKSAN_INITIALIZED || !should_check())
    return calloc(num, size);

  // fprintf(stderr, "[CILKSAN] calloc interposer\n");

  size_t new_size = size * num;
  void *addr = calloc(num, size);
  if (0 == new_size)
    return addr;

  __cilksan_record_alloc(addr, new_size);

  return addr;
}

INTERPOSER(calloc);

CILKSAN_API void wrap_free(void *ptr) {
  // if (__builtin_expect(real_free == NULL, 0)) {
  //   if (-1 == mem_initialized)
  //     return;
  //   initialize_memory_functions();
  // }

  if (!__cilksan_should_check())
    return free(ptr);

  // fprintf(stderr, "[CILKSAN] free interposer\n");
  free(ptr);

  __cilksan_record_free(ptr);
}

INTERPOSER(free);

// CILKSAN_API void* realloc(void *oldaddr, size_t new_size) {
//   if (__builtin_expect(real_realloc == NULL, 0)) {
//     if (-1 == mem_initialized)
//       return NULL;
//     initialize_memory_functions();
//   }

//   if (!TOOL_INITIALIZED || !should_check())
//     return real_realloc(oldaddr, new_size);

//   CheckingRAII nocheck;

//   void *addr = real_realloc(oldaddr, new_size);

//   const size_t *size = malloc_sizes.get((uintptr_t)oldaddr);
//   if (oldaddr != addr) {
//     if (new_size > 0) {
//       // Record the new allocation.
//       CilkSanImpl.clear_shadow_memory((size_t)addr, new_size);
//       malloc_sizes.insert((uintptr_t)addr, new_size);
//     }

//     if (malloc_sizes.contains((uintptr_t)oldaddr)) {
//       // We can't properly mark the freed addresses like writes, so we
//       // just clear the corresponding shadow memory.
//       CilkSanImpl.clear_shadow_memory((size_t)oldaddr, *size);
//       malloc_sizes.remove((uintptr_t)oldaddr);
//     }
//   } else {
//     // We're simply adjusting the allocation at the same place.
//     if (malloc_sizes.contains((uintptr_t)oldaddr)) {
//       size_t old_size = *size;
//       if (old_size < new_size) {
// 	CilkSanImpl.clear_shadow_memory((size_t)addr + old_size,
// 					new_size - old_size);
//       } else if (old_size > new_size) {
// 	// We can't properly mark the freed addresses like writes, so
// 	// we just clear the corresponding shadow memory.
// 	CilkSanImpl.clear_alloc((size_t)oldaddr + new_size,
// 				old_size - new_size);
// 	CilkSanImpl.clear_shadow_memory((size_t)oldaddr + new_size,
// 					old_size - new_size);
//       }
//       malloc_sizes.remove((uintptr_t)addr);
//     }
//     malloc_sizes.insert((uintptr_t)addr, new_size);
//   }

//   return addr;
// }

// CILKSAN_API
// void *mmap(void *start, size_t len, int prot, int flags, int fd, off_t offset) {
//   if (__builtin_expect(real_mmap == NULL, 0)) {
//     if (-1 == mem_initialized)
//       return NULL;
//     initialize_memory_functions();
//   }

//   if (!TOOL_INITIALIZED || !should_check())
//     return real_mmap(start, len, prot, flags, fd, offset);

//   CheckingRAII nocheck;

//   void *r = real_mmap(start, len, prot, flags, fd, offset);

//   CilkSanImpl.record_alloc((size_t)r, len, 0);
//   CilkSanImpl.clear_shadow_memory((size_t)r, len);
//   pages_to_clear.insert({(uintptr_t)r, len});
//   if (!(flags & MAP_ANONYMOUS))
//     // This mmap is backed by a file.  Initialize the shadow memory with a
//     // write to the page.
//     CilkSanImpl.do_write<MAType_t::FNRW>(UNKNOWN_CSI_ID, (uintptr_t)r, len,
// 					 0);
//   return r;
// }

// #if defined(_LARGEFILE64_SOURCE)
// CILKSAN_API
// void *mmap64(void *start, size_t len, int prot, int flags, int fd, off64_t offset) {
//   if (__builtin_expect(real_mmap64 == NULL, 0)) {
//     if (-1 == mem_initialized)
//       return NULL;
//     initialize_memory_functions();
//   }

//   if (!TOOL_INITIALIZED || !should_check())
//     return real_mmap64(start, len, prot, flags, fd, offset);

//   CheckingRAII nocheck;

//   void *r = real_mmap64(start, len, prot, flags, fd, offset);

//   CilkSanImpl.record_alloc((size_t)r, len, 0);
//   CilkSanImpl.clear_shadow_memory((size_t)r, len);
//   pages_to_clear.insert({(uintptr_t)r, len});
//   if (!(flags & MAP_ANONYMOUS))
//     // This mmap is backed by a file.  Initialize the shadow memory with a
//     // write to the page.
//     CilkSanImpl.do_write<MAType_t::FNRW>(UNKNOWN_CSI_ID, (uintptr_t)r, len,
// 					 0);

//   return r;
// }
// #endif // defined(_LARGEFILE64_SOURCE)

// CILKSAN_API
// int munmap(void *start, size_t len) {
//   if (__builtin_expect(real_munmap == NULL, 0)) {
//     if (-1 == mem_initialized)
//       return -1;
//     initialize_memory_functions();
//   }

//   if (!TOOL_INITIALIZED || !should_check())
//     return real_munmap(start, len);

//   CheckingRAII nocheck;

//   int result = real_munmap(start, len);

//   if (0 == result) {
//     auto first_page = pages_to_clear.lower_bound((uintptr_t)start);
//     auto last_page = pages_to_clear.upper_bound((uintptr_t)start + len);
//     for (auto curr_page = first_page; curr_page != last_page; ++curr_page) {
//       // TODO: Treat munmap more like free and record a write operation on the
//       // page.  Need to take care only to write pages that have content in the
//       // shadow memory.  Otherwise, if the application mmap's more virtual
//       // memory than physical memory, then the writes that model page unmapping
//       // can blow out physical memory.
//       CilkSanImpl.clear_shadow_memory((size_t)curr_page->first, curr_page->second);
//       // CilkSanImpl.do_write(UNKNOWN_CSI_ID, curr_page->first, curr_page->second);
//     }
//     pages_to_clear.erase(first_page, last_page);
//   }

//   return result;
// }

// CILKSAN_API
// void *mremap(void *start, size_t old_len, size_t len, int flags, ...) {
// #if defined(MREMAP_FIXED)
//   va_list ap;
//   va_start (ap, flags);
//   void *newaddr = (flags & MREMAP_FIXED) ? va_arg (ap, void *) : NULL;
//   va_end (ap);
// #endif // defined(MREMAP_FIXED)

//   if (__builtin_expect(real_mremap == NULL, 0)) {
//     if (-1 == mem_initialized)
//       return NULL;
//     initialize_memory_functions();
//   }

//   if (!TOOL_INITIALIZED || !should_check()) {
// #if defined(MREMAP_FIXED)
//     return real_mremap(start, old_len, len, flags, newaddr);
// #else
//     return real_mremap(start, old_len, len, flags);
// #endif // defined(MREMAP_FIXED)
//   }

//   CheckingRAII nocheck;

// #if defined(MREMAP_FIXED)
//   void *r = real_mremap(start, old_len, len, flags, newaddr);
// #else
//   void *r = real_mremap(start, old_len, len, flags);
// #endif // defined(MREMAP_FIXED)

//   auto iter = pages_to_clear.find((uintptr_t)start);
//   if (iter != pages_to_clear.end()) {
//     // TODO: Treat mremap more like free and record a write operation
//     // on the page.  Need to take care only to write pages that have
//     // content in the shadow memory.  Otherwise, if the application
//     // mmap's more virtual memory than physical memory, then the
//     // writes that model page unmapping can blow out physical memory.
//     CilkSanImpl.clear_shadow_memory((size_t)iter->first, iter->second);
//     // cilksan_do_write(UNKNOWN_CSI_ID, iter->first, iter->second);
//     pages_to_clear.erase(iter);
//   }
//   // Record the new mapping.
//   CilkSanImpl.record_alloc((size_t)r, len, 0);
//   CilkSanImpl.clear_shadow_memory((size_t)r, len);
//   pages_to_clear.insert({(uintptr_t)r, len});

//   return r;
// }
