// -*- C++ -*-
#ifndef __SYMBOLIZER__
#define __SYMBOLIZER__

#include <cstdint>
#include <mutex>
#include <cstring>
#include <sys/mman.h>

#include "debug_util.h"

#if defined(__linux__)
#  define SANITIZER_LINUX 1
#else
#  define SANITIZER_LINUX 0
#endif

#if defined(__GLIBC__)
#  define SANITIZER_GLIBC 1
#else
#  define SANITIZER_GLIBC 0
#endif

#if defined(__FreeBSD__)
#  define SANITIZER_FREEBSD 1
#else
#  define SANITIZER_FREEBSD 0
#endif

#if defined(__APPLE__)
#  define SANITIZER_MAC 1
#  include <TargetConditionals.h>
#  if TARGET_OS_OSX
#    define SANITIZER_OSX 1
#  else
#    define SANITIZER_OSX 0
#  endif
#else
#  define SANITIZER_MAC 0
#  define SANITIZER_OSX 0
#endif

#if __LP64__
#  define SANITIZER_WORDSIZE 64
#else
#  define SANITIZER_WORDSIZE 32
#endif

#if SANITIZER_WORDSIZE == 64
#  define FIRST_32_SECOND_64(a, b) (b)
#else
#  define FIRST_32_SECOND_64(a, b) (a)
#endif

typedef uintptr_t uptr;
typedef intptr_t sptr;
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int fd_t;
typedef int error_t;

enum ModuleArch {
  kModuleArchUnknown,
  kModuleArchI386,
  kModuleArchX86_64,
  kModuleArchX86_64H,
  kModuleArchARMV6,
  kModuleArchARMV7,
  kModuleArchARMV7S,
  kModuleArchARMV7K,
  kModuleArchARM64,
  kModuleArchRISCV64,
  kModuleArchHexagon
};

using Mutex = std::mutex;

#define CHECK(a)       cilksan_assert((a))
#define CHECK_EQ(a, b) cilksan_assert((u64)(a) == (u64)(b))
#define CHECK_GE(a, b) cilksan_assert((u64)(a) >= (u64)(b))
#define CHECK_GT(a, b) cilksan_assert((u64)(a) > (u64)(b))
#define CHECK_LE(a, b) cilksan_assert((u64)(a) <= (u64)(b))
#define CHECK_LT(a, b) cilksan_assert((u64)(a) < (u64)(b))
#define CHECK_NE(a, b) cilksan_assert((u64)(a) != (u64)(b))
#define UNLIKELY(x)    __builtin_expect(!!(x), 0)

#define UNIMPLEMENTED() cilksan_assert(false && "unimplemented")

#define FORMAT(f, a)  __attribute__((format(printf, f, a)))

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

// I/O
// Define these as macros so we can use them in linker initialized global
// structs without dynamic initialization.
#define kInvalidFd ((fd_t)-1)
// #define kStdinFd ((fd_t)0)
// #define kStdoutFd ((fd_t)1)
// #define kStderrFd ((fd_t)2)

const uptr kMaxPathLength = 4096;

inline const char *StripModuleName(const char *module) {
  if (!module)
    return nullptr;
  if (const char *slash_pos = std::strrchr(module, '/')) {
    return slash_pos + 1;
  }
  return module;
}

char **GetEnviron();

uptr ReadBinaryName(/*out*/char *buf, uptr buf_len);
uptr ReadBinaryNameCached(/*out*/char *buf, uptr buf_len);
uptr ReadLongProcessName(/*out*/ char *buf, uptr buf_len);

inline bool internal_iserror(uptr retval, int *rverrno) {
  if (retval == (uptr)-1) {
    if (rverrno)
      *rverrno = errno;
    return true;
  } else {
    return false;
  }
}

inline const char *internal_strchrnul(const char *s, int c) {
  const char *res = std::strchr(s, c);
  if (!res)
    res = const_cast<char *>(s) + std::strlen(s);
  return res;
}

#if SANITIZER_MAC
fd_t internal_spawn(const char *argv[], const char *envp[], pid_t *pid);
#endif

inline uptr GetPageSizeCached() {
  return 4096;
}

inline uptr MostSignificantSetBitIndex(uptr x) {
  CHECK_NE(x, 0U);
  unsigned long up;
  up = (8 * sizeof(uptr)) - 1 - __builtin_clzl(x);
  return up;
}

inline constexpr bool IsPowerOfTwo(uptr x) { return (x & (x - 1)) == 0; }

inline uptr RoundUpToPowerOfTwo(uptr size) {
  CHECK(size);
  if (IsPowerOfTwo(size)) return size;

  uptr up = MostSignificantSetBitIndex(size);
  CHECK_LT(size, (1ULL << (up + 1)));
  CHECK_GT(size, (1ULL << up));
  return 1ULL << (up + 1);
}

inline constexpr uptr RoundUpTo(uptr size, uptr boundary) {
  CHECK(IsPowerOfTwo(boundary));
  return (size + boundary - 1) & ~(boundary - 1);
}

inline void *MmapOrDie(uptr size, const char *mem_type, bool raw_report = false) {
  size = RoundUpTo(size, GetPageSizeCached());
  // uptr res = MmapNamed(nullptr, size, PROT_READ | PROT_WRITE,
  //                      MAP_PRIVATE | MAP_ANON, mem_type);
  void *res = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
                  -1, 0);
  int reserrno;
  if (UNLIKELY(internal_iserror((uptr)res, &reserrno))) {
    perror("Error from mmap");
    cilksan_assert(false && "Failed to mmap storage");
  }
  // IncreaseTotalMmap(size);
  return (void *)res;
}

inline void UnmapOrDie(void *addr, uptr size) {
  if (!addr || !size) return;
  uptr res = munmap(addr, size);
  if (UNLIKELY(internal_iserror(res, nullptr))) {
    // Report("ERROR: %s failed to deallocate 0x%zx (%zd) bytes at address %p\n",
    //        SanitizerToolName, size, size, addr);
    perror("Error from munmap");
    CHECK(false && "Failed to unmap");
  }
  // DecreaseTotalMmap(size);
}

///////////////////////////////////////////////////////////////////////////

template <typename Fn>
class RunOnDestruction {
 public:
  explicit RunOnDestruction(Fn fn) : fn_(fn) {}
  ~RunOnDestruction() { fn_(); }

 private:
  Fn fn_;
};

// A simple scope guard. Usage:
// auto cleanup = at_scope_exit([]{ do_cleanup; });
template <typename Fn>
RunOnDestruction<Fn> at_scope_exit(Fn fn) {
  return RunOnDestruction<Fn>(fn);
}

// Intrusive singly-linked list with size(), push_back(), push_front()
// pop_front(), append_front() and append_back().
// This class should be a POD (so that it can be put into TLS)
// and an object with all zero fields should represent a valid empty list.
// This class does not have a CTOR, so clear() should be called on all
// non-zero-initialized objects before using.
template<class Item>
struct IntrusiveList {
  friend class Iterator;

  void clear() {
    first_ = last_ = nullptr;
    size_ = 0;
  }

  bool empty() const { return size_ == 0; }
  uptr size() const { return size_; }

  void push_back(Item *x) {
    if (empty()) {
      x->next = nullptr;
      first_ = last_ = x;
      size_ = 1;
    } else {
      x->next = nullptr;
      last_->next = x;
      last_ = x;
      size_++;
    }
  }

  void push_front(Item *x) {
    if (empty()) {
      x->next = nullptr;
      first_ = last_ = x;
      size_ = 1;
    } else {
      x->next = first_;
      first_ = x;
      size_++;
    }
  }

  void pop_front() {
    CHECK(!empty());
    first_ = first_->next;
    if (!first_)
      last_ = nullptr;
    size_--;
  }

  void extract(Item *prev, Item *x) {
    CHECK(!empty());
    CHECK_NE(prev, nullptr);
    CHECK_NE(x, nullptr);
    CHECK_EQ(prev->next, x);
    prev->next = x->next;
    if (last_ == x)
      last_ = prev;
    size_--;
  }

  Item *front() { return first_; }
  const Item *front() const { return first_; }
  Item *back() { return last_; }
  const Item *back() const { return last_; }

  void append_front(IntrusiveList<Item> *l) {
    CHECK_NE(this, l);
    if (l->empty())
      return;
    if (empty()) {
      *this = *l;
    } else if (!l->empty()) {
      l->last_->next = first_;
      first_ = l->first_;
      size_ += l->size();
    }
    l->clear();
  }

  void append_back(IntrusiveList<Item> *l) {
    CHECK_NE(this, l);
    if (l->empty())
      return;
    if (empty()) {
      *this = *l;
    } else {
      last_->next = l->first_;
      last_ = l->last_;
      size_ += l->size();
    }
    l->clear();
  }

  void CheckConsistency() {
    if (size_ == 0) {
      CHECK_EQ(first_, 0);
      CHECK_EQ(last_, 0);
    } else {
      uptr count = 0;
      for (Item *i = first_; ; i = i->next) {
        count++;
        if (i == last_) break;
      }
      CHECK_EQ(size(), count);
      CHECK_EQ(last_->next, 0);
    }
  }

  template<class ItemTy>
  class IteratorBase {
   public:
    explicit IteratorBase(ItemTy *current) : current_(current) {}
    IteratorBase &operator++() {
      current_ = current_->next;
      return *this;
    }
    bool operator!=(IteratorBase other) const {
      return current_ != other.current_;
    }
    ItemTy &operator*() {
      return *current_;
    }
   private:
    ItemTy *current_;
  };

  typedef IteratorBase<Item> Iterator;
  typedef IteratorBase<const Item> ConstIterator;

  Iterator begin() { return Iterator(first_); }
  Iterator end() { return Iterator(0); }

  ConstIterator begin() const { return ConstIterator(first_); }
  ConstIterator end() const { return ConstIterator(0); }

// private, don't use directly.
  uptr size_;
  Item *first_;
  Item *last_;
};

///////////////////////////////////////////////////////////////////////////

// Simple low-level (mmap-based) allocator for internal use. Doesn't have
// constructor, so all instances of LowLevelAllocator should be
// linker initialized.
class LowLevelAllocator {
 public:
  // Requires an external lock.
  void *Allocate(uptr size);
 private:
  char *allocated_end_;
  char *allocated_current_;
};

inline void *operator new(size_t size, LowLevelAllocator &alloc) {
  return alloc.Allocate(size);
}

// Don't use std::min, std::max or std::swap, to minimize dependency
// on libstdc++.
template <class T>
constexpr T Min(T a, T b) {
  return a < b ? a : b;
}
template <class T>
constexpr T Max(T a, T b) {
  return a > b ? a : b;
}
// template <class T>
// constexpr T Abs(T a) {
//   return a < 0 ? -a : a;
// }
template<class T> void Swap(T& a, T& b) {
  T tmp = a;
  a = b;
  b = tmp;
}

// Char handling
inline bool IsSpace(int c) {
  return (c == ' ') || (c == '\n') || (c == '\t') ||
         (c == '\f') || (c == '\r') || (c == '\v');
}
inline bool IsDigit(int c) {
  return (c >= '0') && (c <= '9');
}
inline int ToLower(int c) {
  return (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c;
}

///////////////////////////////////////////////////////////////////////////

// A low-level vector based on mmap. May incur a significant memory overhead for
// small vectors.
// WARNING: The current implementation supports only POD types.
template<typename T>
class InternalMmapVectorNoCtor {
 public:
  using value_type = T;
  void Initialize(uptr initial_capacity) {
    capacity_bytes_ = 0;
    size_ = 0;
    data_ = 0;
    reserve(initial_capacity);
  }
  void Destroy() { UnmapOrDie(data_, capacity_bytes_); }
  T &operator[](uptr i) {
    CHECK_LT(i, size_);
    return data_[i];
  }
  const T &operator[](uptr i) const {
    CHECK_LT(i, size_);
    return data_[i];
  }
  void push_back(const T &element) {
    CHECK_LE(size_, capacity());
    if (size_ == capacity()) {
      uptr new_capacity = RoundUpToPowerOfTwo(size_ + 1);
      Realloc(new_capacity);
    }
    std::memcpy(&data_[size_++], &element, sizeof(T));
  }
  T &back() {
    CHECK_GT(size_, 0);
    return data_[size_ - 1];
  }
  void pop_back() {
    CHECK_GT(size_, 0);
    size_--;
  }
  uptr size() const {
    return size_;
  }
  const T *data() const {
    return data_;
  }
  T *data() {
    return data_;
  }
  uptr capacity() const { return capacity_bytes_ / sizeof(T); }
  void reserve(uptr new_size) {
    // Never downsize internal buffer.
    if (new_size > capacity())
      Realloc(new_size);
  }
  void resize(uptr new_size) {
    if (new_size > size_) {
      reserve(new_size);
      std::memset(&data_[size_], 0, sizeof(T) * (new_size - size_));
    }
    size_ = new_size;
  }

  void clear() { size_ = 0; }
  bool empty() const { return size() == 0; }

  const T *begin() const {
    return data();
  }
  T *begin() {
    return data();
  }
  const T *end() const {
    return data() + size();
  }
  T *end() {
    return data() + size();
  }

  void swap(InternalMmapVectorNoCtor &other) {
    Swap(data_, other.data_);
    Swap(capacity_bytes_, other.capacity_bytes_);
    Swap(size_, other.size_);
  }

 private:
  void Realloc(uptr new_capacity) {
    CHECK_GT(new_capacity, 0);
    CHECK_LE(size_, new_capacity);
    uptr new_capacity_bytes =
        RoundUpTo(new_capacity * sizeof(T), GetPageSizeCached());
    T *new_data = (T *)MmapOrDie(new_capacity_bytes, "InternalMmapVector");
    std::memcpy(new_data, data_, size_ * sizeof(T));
    UnmapOrDie(data_, capacity_bytes_);
    data_ = new_data;
    capacity_bytes_ = new_capacity_bytes;
  }

  T *data_;
  uptr capacity_bytes_;
  uptr size_;
};

template <typename T>
bool operator==(const InternalMmapVectorNoCtor<T> &lhs,
                const InternalMmapVectorNoCtor<T> &rhs) {
  if (lhs.size() != rhs.size()) return false;
  return std::memcmp(lhs.data(), rhs.data(), lhs.size() * sizeof(T)) == 0;
}

template <typename T>
bool operator!=(const InternalMmapVectorNoCtor<T> &lhs,
                const InternalMmapVectorNoCtor<T> &rhs) {
  return !(lhs == rhs);
}

template<typename T>
class InternalMmapVector : public InternalMmapVectorNoCtor<T> {
 public:
  InternalMmapVector() { InternalMmapVectorNoCtor<T>::Initialize(0); }
  explicit InternalMmapVector(uptr cnt) {
    InternalMmapVectorNoCtor<T>::Initialize(cnt);
    this->resize(cnt);
  }
  ~InternalMmapVector() { InternalMmapVectorNoCtor<T>::Destroy(); }
  // Disallow copies and moves.
  InternalMmapVector(const InternalMmapVector &) = delete;
  InternalMmapVector &operator=(const InternalMmapVector &) = delete;
  InternalMmapVector(InternalMmapVector &&) = delete;
  InternalMmapVector &operator=(InternalMmapVector &&) = delete;
};

class InternalScopedString {
 public:
  InternalScopedString() : buffer_(1) { buffer_[0] = '\0'; }

  uptr length() const { return buffer_.size() - 1; }
  void clear() {
    buffer_.resize(1);
    buffer_[0] = '\0';
  }
  void append(const char *format, ...) FORMAT(2, 3);
  const char *data() const { return buffer_.data(); }
  char *data() { return buffer_.data(); }

 private:
  InternalMmapVector<char> buffer_;
};

static const uptr kModuleUUIDSize = 32;
static const uptr kMaxSegName = 16;

class LoadedModule;

// Contains information used to iterate through sections.
struct MemoryMappedSegmentData {
  char name[kMaxSegName];
  uptr nsects;
  const char *current_load_cmd_addr;
  u32 lc_type;
  uptr base_virt_addr;
  uptr addr_mask;
};

// Memory protection masks.
static const uptr kProtectionRead = 1;
static const uptr kProtectionWrite = 2;
static const uptr kProtectionExecute = 4;
static const uptr kProtectionShared = 8;

class MemoryMappedSegment {
 public:
  explicit MemoryMappedSegment(char *buff = nullptr, uptr size = 0)
      : filename(buff), filename_size(size), data_(nullptr) {}
  ~MemoryMappedSegment() {}

  bool IsReadable() const { return protection & kProtectionRead; }
  bool IsWritable() const { return protection & kProtectionWrite; }
  bool IsExecutable() const { return protection & kProtectionExecute; }
  bool IsShared() const { return protection & kProtectionShared; }

  void AddAddressRanges(LoadedModule *module);

  uptr start;
  uptr end;
  uptr offset;
  char *filename;  // owned by caller
  uptr filename_size;
  uptr protection;
  ModuleArch arch;
  u8 uuid[kModuleUUIDSize];

 private:
  friend class MemoryMappingLayout;

  // This field is assigned and owned by MemoryMappingLayout if needed
  MemoryMappedSegmentData *data_;
};

class MemoryMappingLayoutBase {
 public:
  virtual bool Next(MemoryMappedSegment *segment) { UNIMPLEMENTED(); }
  virtual bool Error() const { UNIMPLEMENTED(); };
  virtual void Reset() { UNIMPLEMENTED(); }

 protected:
  ~MemoryMappingLayoutBase() {}
};

// Get the definition of MemoryMappingLayoutData from the
// platform-specific header.
#if SANITIZER_MAC
#include "symbolizer_mac.h"
#elif SANITIZER_LINUX
#include "symbolizer_linux.h"
#endif

struct MemoryMappingLayoutData;

class MemoryMappingLayout final : public MemoryMappingLayoutBase {
 public:
  explicit MemoryMappingLayout(bool cache_enabled);
  ~MemoryMappingLayout();
  virtual bool Next(MemoryMappedSegment *segment) override;
  virtual bool Error() const override;
  virtual void Reset() override;
  // In some cases, e.g. when running under a sandbox on Linux, ASan is unable
  // to obtain the memory mappings. It should fall back to pre-cached data
  // instead of aborting.
  static void CacheMemoryMappings();

  // Adds all mapped objects into a vector.
  void DumpListOfModules(InternalMmapVectorNoCtor<LoadedModule> *modules);

 private:
  void LoadFromCache();

  MemoryMappingLayoutData data_;
};

///////////////////////////////////////////////////////////////////////////

constexpr uptr kDefaultFileMaxSize = FIRST_32_SECOND_64(1 << 26, 1 << 28);

// Opens the file 'file_name" and reads up to 'max_len' bytes.
// This function is less I/O efficient than ReadFileToVector as it may reread
// file multiple times to avoid mmap during read attempts. It's used to read
// procmap, so short reads with mmap in between can produce inconsistent result.
// The resulting buffer is mmaped and stored in '*buff'.
// The size of the mmaped region is stored in '*buff_size'.
// The total number of read bytes is stored in '*read_len'.
// Returns true if file was successfully opened and read.
bool ReadFileToBuffer(const char *file_name, char **buff, uptr *buff_size,
                      uptr *read_len, uptr max_len = kDefaultFileMaxSize,
                      error_t *errno_p = nullptr);

// When adding a new architecture, don't forget to also update
// script/asan_symbolize.py and sanitizer_symbolizer_libcdep.cpp.
inline const char *ModuleArchToString(ModuleArch arch) {
  switch (arch) {
    case kModuleArchUnknown:
      return "";
    case kModuleArchI386:
      return "i386";
    case kModuleArchX86_64:
      return "x86_64";
    case kModuleArchX86_64H:
      return "x86_64h";
    case kModuleArchARMV6:
      return "armv6";
    case kModuleArchARMV7:
      return "armv7";
    case kModuleArchARMV7S:
      return "armv7s";
    case kModuleArchARMV7K:
      return "armv7k";
    case kModuleArchARM64:
      return "arm64";
    case kModuleArchRISCV64:
      return "riscv64";
    case kModuleArchHexagon:
      return "hexagon";
  }
  CHECK(0 && "Invalid module arch");
  return "";
}

// Represents a binary loaded into virtual memory (e.g. this can be an
// executable or a shared object).
class LoadedModule {
 public:
  LoadedModule()
      : full_name_(nullptr),
        base_address_(0),
        max_executable_address_(0),
        arch_(kModuleArchUnknown),
        uuid_size_(0),
        instrumented_(false) {
    std::memset(uuid_, 0, kModuleUUIDSize);
    ranges_.clear();
  }
  void set(const char *module_name, uptr base_address);
  void set(const char *module_name, uptr base_address, ModuleArch arch,
           u8 uuid[kModuleUUIDSize], bool instrumented);
  void setUuid(const char *uuid, uptr size);
  void clear();
  void addAddressRange(uptr beg, uptr end, bool executable, bool writable,
                       const char *name = nullptr);
  bool containsAddress(uptr address) const;

  const char *full_name() const { return full_name_; }
  uptr base_address() const { return base_address_; }
  uptr max_executable_address() const { return max_executable_address_; }
  ModuleArch arch() const { return arch_; }
  const u8 *uuid() const { return uuid_; }
  uptr uuid_size() const { return uuid_size_; }
  bool instrumented() const { return instrumented_; }

  struct AddressRange {
    AddressRange *next;
    uptr beg;
    uptr end;
    bool executable;
    bool writable;
    char name[kMaxSegName];

    AddressRange(uptr beg, uptr end, bool executable, bool writable,
                 const char *name)
        : next(nullptr),
          beg(beg),
          end(end),
          executable(executable),
          writable(writable) {
      std::strncpy(this->name, (name ? name : ""), ARRAY_SIZE(this->name));
    }
  };

  const IntrusiveList<AddressRange> &ranges() const { return ranges_; }

 private:
  char *full_name_;  // Owned.
  uptr base_address_;
  uptr max_executable_address_;
  ModuleArch arch_;
  uptr uuid_size_;
  u8 uuid_[kModuleUUIDSize];
  bool instrumented_;
  IntrusiveList<AddressRange> ranges_;
};

// List of LoadedModules. OS-dependent implementation is responsible for
// filling this information.
class ListOfModules {
 public:
  ListOfModules() : initialized(false) {}
  ~ListOfModules() { clear(); }
  void init();
  void fallbackInit();  // Uses fallback init if available, otherwise clears
  const LoadedModule *begin() const { return modules_.begin(); }
  LoadedModule *begin() { return modules_.begin(); }
  const LoadedModule *end() const { return modules_.end(); }
  LoadedModule *end() { return modules_.end(); }
  uptr size() const { return modules_.size(); }
  const LoadedModule &operator[](uptr i) const {
    CHECK_LT(i, modules_.size());
    return modules_[i];
  }

 private:
  void clear() {
    for (auto &module : modules_) module.clear();
    modules_.clear();
  }
  void clearOrInit() {
    initialized ? clear() : modules_.Initialize(kInitialCapacity);
    initialized = true;
  }

  InternalMmapVectorNoCtor<LoadedModule> modules_;
  // We rarely have more than 16K loaded modules.
  static const uptr kInitialCapacity = 1 << 14;
  bool initialized;
};

struct AddressInfo {
  // Owns all the string members. Storage for them is
  // (de)allocated using sanitizer internal allocator.
  uptr address;

  char *module;
  uptr module_offset;
  ModuleArch module_arch;
  u8 uuid[kModuleUUIDSize];
  uptr uuid_size;

  static const uptr kUnknown = ~(uptr)0;
  char *function;
  uptr function_offset;

  char *file;
  int line;
  int column;

  AddressInfo();
  // Deletes all strings and resets all fields.
  void Clear();
  void FillModuleInfo(const char *mod_name, uptr mod_offset, ModuleArch arch);
  void FillModuleInfo(const LoadedModule &mod);
  uptr module_base() const { return address - module_offset; }
};

// Linked list of symbolized frames (each frame is described by AddressInfo).
struct SymbolizedStack {
  SymbolizedStack *next;
  AddressInfo info;
  static SymbolizedStack *New(uptr addr);
  // Deletes current, and all subsequent frames in the linked list.
  // The object cannot be accessed after the call to this function.
  void ClearAll();

 private:
  SymbolizedStack(): next(nullptr), info() {}
};

// For now, DataInfo is used to describe global variable.
struct DataInfo {
  // Owns all the string members. Storage for them is
  // (de)allocated using sanitizer internal allocator.
  char *module;
  uptr module_offset;
  ModuleArch module_arch;

  char *file;
  uptr line;
  char *name;
  uptr start;
  uptr size;

  DataInfo();
  void Clear();
};

struct LocalInfo {
  char *function_name = nullptr;
  char *name = nullptr;
  char *decl_file = nullptr;
  unsigned decl_line = 0;

  bool has_frame_offset = false;
  bool has_size = false;
  bool has_tag_offset = false;

  sptr frame_offset;
  uptr size;
  uptr tag_offset;

  void Clear();
};

struct FrameInfo {
  char *module;
  uptr module_offset;
  ModuleArch module_arch;

  InternalMmapVector<LocalInfo> locals;
  void Clear();
};

class SymbolizerTool;

class Symbolizer final {
 public:
  /// Initialize and return platform-specific implementation of symbolizer
  /// (if it wasn't already initialized).
  static Symbolizer *GetOrInit();
  static void LateInitialize();
  // Returns a list of symbolized frames for a given address (containing
  // all inlined functions, if necessary).
  SymbolizedStack *SymbolizePC(uptr address);
  bool SymbolizeData(uptr address, DataInfo *info);
  bool SymbolizeFrame(uptr address, FrameInfo *info);

  // The module names Symbolizer returns are stable and unique for every given
  // module.  It is safe to store and compare them as pointers.
  bool GetModuleNameAndOffsetForPC(uptr pc, const char **module_name,
                                   uptr *module_address);
  const char *GetModuleNameForPc(uptr pc) {
    const char *module_name = nullptr;
    uptr unused;
    if (GetModuleNameAndOffsetForPC(pc, &module_name, &unused))
      return module_name;
    return nullptr;
  }

  // Release internal caches (if any).
  void Flush();
  // Attempts to demangle the provided C++ mangled name.
  const char *Demangle(const char *name);

  // Allow user to install hooks that would be called before/after Symbolizer
  // does the actual file/line info fetching. Specific sanitizers may need this
  // to distinguish system library calls made in user code from calls made
  // during in-process symbolization.
  typedef void (*StartSymbolizationHook)();
  typedef void (*EndSymbolizationHook)();
  // May be called at most once.
  void AddHooks(StartSymbolizationHook start_hook,
                EndSymbolizationHook end_hook);

  void RefreshModules();
  const LoadedModule *FindModuleForAddress(uptr address);

  void InvalidateModuleList();

 private:
  // GetModuleNameAndOffsetForPC has to return a string to the caller.
  // Since the corresponding module might get unloaded later, we should create
  // our owned copies of the strings that we can safely return.
  // ModuleNameOwner does not provide any synchronization, thus calls to
  // its method should be protected by |mu_|.
  class ModuleNameOwner {
   public:
    explicit ModuleNameOwner(Mutex *synchronized_by)
        : last_match_(nullptr), mu_(synchronized_by) {
      storage_.reserve(kInitialCapacity);
    }
    const char *GetOwnedCopy(const char *str);

   private:
    static const uptr kInitialCapacity = 1000;
    InternalMmapVector<const char*> storage_;
    const char *last_match_;

    Mutex *mu_;
  } module_names_;

  /// Platform-specific function for creating a Symbolizer object.
  static Symbolizer *PlatformInit();

  bool FindModuleNameAndOffsetForAddress(uptr address, const char **module_name,
                                         uptr *module_offset,
                                         ModuleArch *module_arch);
  ListOfModules modules_;
  ListOfModules fallback_modules_;
  // If stale, need to reload the modules before looking up addresses.
  bool modules_fresh_;

  // Platform-specific default demangler, must not return nullptr.
  const char *PlatformDemangle(const char *name);

  static Symbolizer *symbolizer_;
  // static StaticSpinMutex init_mu_;
  static std::mutex init_mu_;

  // Mutex locked from public methods of |Symbolizer|, so that the internals
  // (including individual symbolizer tools and platform-specific methods) are
  // always synchronized.
  Mutex mu_;

  IntrusiveList<SymbolizerTool> tools_;

  explicit Symbolizer(IntrusiveList<SymbolizerTool> tools);

  static LowLevelAllocator symbolizer_allocator_;

  StartSymbolizationHook start_hook_;
  EndSymbolizationHook end_hook_;
  class SymbolizerScope {
   public:
    explicit SymbolizerScope(const Symbolizer *sym);
    ~SymbolizerScope();
   private:
    const Symbolizer *sym_;
  };
};

#endif // __SYMBOLIZER__
