#include <cstdio>
#include <fcntl.h>
#include <spawn.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug_util.h"
#include "symbolizer.h"

///////////////////////////////////////////////////////////////////////////
/// Copied from compiler_rt/lib/sanitizer*

///////////////////////////////////////////////////////////////////////////

enum FileAccessMode {
  RdOnly,
  WrOnly,
  RdWr
};

fd_t ReserveStandardFds(fd_t fd) {
  CHECK_GE(fd, 0);
  if (fd > 2)
    return fd;
  bool used[3];
  std::memset(used, 0, sizeof(used));
  while (fd <= 2) {
    used[fd] = true;
    fd = dup(fd);
  }
  for (int i = 0; i <= 2; ++i)
    if (used[i])
      close(i);
  return fd;
}

fd_t OpenFile(const char *filename, FileAccessMode mode, error_t *errno_p) {
  // if (ShouldMockFailureToOpen(filename))
  //   return kInvalidFd;
  int flags;
  switch (mode) {
    case RdOnly: flags = O_RDONLY; break;
    case WrOnly: flags = O_WRONLY | O_CREAT | O_TRUNC; break;
    case RdWr: flags = O_RDWR | O_CREAT; break;
  }
  fd_t res = open(filename, flags, 0660);
  if (internal_iserror(res, errno_p))
    return kInvalidFd;
  return ReserveStandardFds(res);
}

static void CloseFile(fd_t fd) {
  close(fd);
}

static bool ReadFromFile(fd_t fd, void *buff, uptr buff_size, uptr *bytes_read,
                  error_t *error_p = nullptr) {
  uptr res = read(fd, buff, buff_size);
  if (internal_iserror(res, error_p))
    return false;
  if (bytes_read)
    *bytes_read = res;
  return true;
}

static bool WriteToFile(fd_t fd, const void *buff, uptr buff_size, uptr *bytes_written,
                 error_t *error_p = nullptr) {
  uptr res = write(fd, buff, buff_size);
  if (internal_iserror(res, error_p))
    return false;
  if (bytes_written)
    *bytes_written = res;
  return true;
}

bool ReadFileToBuffer(const char *file_name, char **buff, uptr *buff_size,
                      uptr *read_len, uptr max_len, error_t *errno_p) {
  *buff = nullptr;
  *buff_size = 0;
  *read_len = 0;
  if (!max_len)
    return true;
  uptr PageSize = GetPageSizeCached();
  uptr kMinFileLen = Min(PageSize, max_len);

  // The files we usually open are not seekable, so try different buffer sizes.
  for (uptr size = kMinFileLen;; size = Min(size * 2, max_len)) {
    UnmapOrDie(*buff, *buff_size);
    *buff = (char*)MmapOrDie(size, __func__);
    *buff_size = size;
    fd_t fd = OpenFile(file_name, RdOnly, errno_p);
    if (fd == kInvalidFd) {
      UnmapOrDie(*buff, *buff_size);
      return false;
    }
    *read_len = 0;
    // Read up to one page at a time.
    bool reached_eof = false;
    while (*read_len < size) {
      uptr just_read;
      if (!ReadFromFile(fd, *buff + *read_len, size - *read_len, &just_read,
                        errno_p)) {
        UnmapOrDie(*buff, *buff_size);
        CloseFile(fd);
        return false;
      }
      *read_len += just_read;
      if (just_read == 0 || *read_len == max_len) {
        reached_eof = true;
        break;
      }
    }
    CloseFile(fd);
    if (reached_eof)  // We've read the whole file.
      break;
  }
  return true;
}

constexpr uptr kLowLevelAllocatorDefaultAlignment = 8;
static uptr low_level_alloc_min_alignment = kLowLevelAllocatorDefaultAlignment;

void *LowLevelAllocator::Allocate(uptr size) {
  // Align allocation size.
  size = RoundUpTo(size, low_level_alloc_min_alignment);
  if (allocated_end_ - allocated_current_ < (sptr)size) {
    uptr size_to_allocate = RoundUpTo(size, GetPageSizeCached());
    allocated_current_ =
        (char*)MmapOrDie(size_to_allocate, __func__);
    allocated_end_ = allocated_current_ + size_to_allocate;
    // if (low_level_alloc_callback) {
    //   low_level_alloc_callback((uptr)allocated_current_,
    //                            size_to_allocate);
    // }
  }
  CHECK(allocated_end_ - allocated_current_ >= (sptr)size);
  void *res = allocated_current_;
  allocated_current_ += size;
  return res;
}

void LoadedModule::set(const char *module_name, uptr base_address) {
  clear();
  full_name_ = strdup(module_name);
  base_address_ = base_address;
}

void LoadedModule::set(const char *module_name, uptr base_address,
                       ModuleArch arch, u8 uuid[kModuleUUIDSize],
                       bool instrumented) {
  set(module_name, base_address);
  arch_ = arch;
  std::memcpy(uuid_, uuid, sizeof(uuid_));
  uuid_size_ = kModuleUUIDSize;
  instrumented_ = instrumented;
}

void LoadedModule::setUuid(const char *uuid, uptr size) {
  if (size > kModuleUUIDSize)
    size = kModuleUUIDSize;
  std::memcpy(uuid_, uuid, size);
  uuid_size_ = size;
}

void LoadedModule::clear() {
  free(full_name_);
  base_address_ = 0;
  max_executable_address_ = 0;
  full_name_ = nullptr;
  arch_ = kModuleArchUnknown;
  std::memset(uuid_, 0, kModuleUUIDSize);
  instrumented_ = false;
  while (!ranges_.empty()) {
    AddressRange *r = ranges_.front();
    ranges_.pop_front();
    free(r);
  }
}

void LoadedModule::addAddressRange(uptr beg, uptr end, bool executable,
                                   bool writable, const char *name) {
  // void *mem = InternalAlloc(sizeof(AddressRange));
  void *mem = malloc(sizeof(AddressRange));
  AddressRange *r =
      new(mem) AddressRange(beg, end, executable, writable, name);
  ranges_.push_back(r);
  if (executable && end > max_executable_address_)
    max_executable_address_ = end;
}

bool LoadedModule::containsAddress(uptr address) const {
  for (const AddressRange &r : ranges()) {
    if (r.beg <= address && address < r.end)
      return true;
  }
  return false;
}

AddressInfo::AddressInfo() {
  std::memset(this, 0, sizeof(AddressInfo));
  function_offset = kUnknown;
}

void AddressInfo::Clear() {
  free(module);
  free(function);
  free(file);
  std::memset(this, 0, sizeof(AddressInfo));
  function_offset = kUnknown;
  uuid_size = 0;
}

void AddressInfo::FillModuleInfo(const char *mod_name, uptr mod_offset,
                                 ModuleArch mod_arch) {
  module = strdup(mod_name);
  module_offset = mod_offset;
  module_arch = mod_arch;
  uuid_size = 0;
}

void AddressInfo::FillModuleInfo(const LoadedModule &mod) {
  module = strdup(mod.full_name());
  module_offset = address - mod.base_address();
  module_arch = mod.arch();
  if (mod.uuid_size())
    std::memcpy(uuid, mod.uuid(), mod.uuid_size());
  uuid_size = mod.uuid_size();
}

SymbolizedStack *SymbolizedStack::New(uptr addr) {
  void *mem = malloc(sizeof(SymbolizedStack));
  SymbolizedStack *res = new(mem) SymbolizedStack();
  res->info.address = addr;
  return res;
}

void SymbolizedStack::ClearAll() {
  info.Clear();
  if (next)
    next->ClearAll();
  free(this);
}

DataInfo::DataInfo() {
  std::memset(this, 0, sizeof(DataInfo));
}

void DataInfo::Clear() {
  free(module);
  free(file);
  free(name);
  std::memset(this, 0, sizeof(DataInfo));
}

void FrameInfo::Clear() {
  free(module);
  for (LocalInfo &local : locals) {
    free(local.function_name);
    free(local.name);
    free(local.decl_file);
  }
  locals.clear();
}

///////////////////////////////////////////////////////////////////////////

static char binary_name_cache_str[kMaxPathLength];
static char process_name_cache_str[kMaxPathLength];

const char *GetProcessName() {
  return process_name_cache_str;
}

static uptr ReadProcessName(/*out*/ char *buf, uptr buf_len) {
  ReadLongProcessName(buf, buf_len);
  char *s = const_cast<char *>(StripModuleName(buf));
  uptr len = std::strlen(s);
  if (s != buf) {
    std::memmove(buf, s, len);
    buf[len] = '\0';
  }
  return len;
}

// Call once to make sure that binary_name_cache_str is initialized
void CacheBinaryName() {
  if (binary_name_cache_str[0] != '\0')
    return;
  ReadBinaryName(binary_name_cache_str, sizeof(binary_name_cache_str));
  ReadProcessName(process_name_cache_str, sizeof(process_name_cache_str));
}

uptr ReadBinaryNameCached(/*out*/char *buf, uptr buf_len) {
  CacheBinaryName();
  uptr name_len = std::strlen(binary_name_cache_str);
  name_len = (name_len < buf_len - 1) ? name_len : buf_len - 1;
  if (buf_len == 0)
    return 0;
  std::memcpy(buf, binary_name_cache_str, name_len);
  buf[name_len] = '\0';
  return name_len;
}

uptr ReadBinaryDir(/*out*/ char *buf, uptr buf_len) {
  ReadBinaryNameCached(buf, buf_len);
  const char *exec_name_pos = StripModuleName(buf);
  uptr name_len = exec_name_pos - buf;
  buf[name_len] = '\0';
  return name_len;
}

static bool FileExists(const char *filename) {
  // if (ShouldMockFailureToOpen(filename))
  //   return false;
  struct stat st;
  if (stat(filename, &st))
    return false;
  // Sanity check: filename is a regular file.
  return S_ISREG(st.st_mode);
}

void SleepForMillis(unsigned millis) { usleep((u64)millis * 1000); }

pid_t StartSubprocess(const char *program, const char *const argv[],
                      const char *const envp[], fd_t stdin_fd = kInvalidFd,
                      fd_t stdout_fd = kInvalidFd,
                      fd_t stderr_fd = kInvalidFd) {
  auto file_closer = at_scope_exit([&] {
    if (stdin_fd != kInvalidFd) {
      close(stdin_fd);
    }
    if (stdout_fd != kInvalidFd) {
      close(stdout_fd);
    }
    if (stderr_fd != kInvalidFd) {
      close(stderr_fd);
    }
  });

  int pid = fork();

  if (pid < 0) {
    int rverrno;
    if (internal_iserror(pid, &rverrno)) {
      // Report("WARNING: failed to fork (errno %d)\n", rverrno);
    }
    return pid;
  }

  if (pid == 0) {
    // Child subprocess
    if (stdin_fd != kInvalidFd) {
      close(STDIN_FILENO);
      dup2(stdin_fd, STDIN_FILENO);
      close(stdin_fd);
    }
    if (stdout_fd != kInvalidFd) {
      close(STDOUT_FILENO);
      dup2(stdout_fd, STDOUT_FILENO);
      close(stdout_fd);
    }
    if (stderr_fd != kInvalidFd) {
      close(STDERR_FILENO);
      dup2(stderr_fd, STDERR_FILENO);
      close(stderr_fd);
    }

    for (int fd = sysconf(_SC_OPEN_MAX); fd > 2; fd--) close(fd);

    execve(program, const_cast<char **>(&argv[0]),
                    const_cast<char *const *>(envp));
    _exit(1);
  }

  return pid;
}

bool IsProcessRunning(pid_t pid) {
  int process_status;
  uptr waitpid_status = waitpid(pid, &process_status, WNOHANG);
  int local_errno;
  if (internal_iserror(waitpid_status, &local_errno)) {
    // VReport(1, "Waiting on the process failed (errno %d).\n", local_errno);
    return false;
  }
  return waitpid_status == 0;
}

///////////////////////////////////////////////////////////////////////////

// SymbolizerTool is an interface that is implemented by individual "tools"
// that can perform symbolication (external llvm-symbolizer, libbacktrace,
// Windows DbgHelp symbolizer, etc.).
class SymbolizerTool {
 public:
  // The main |Symbolizer| class implements a "fallback chain" of symbolizer
  // tools. In a request to symbolize an address, if one tool returns false,
  // the next tool in the chain will be tried.
  SymbolizerTool *next;

  SymbolizerTool() : next(nullptr) { }

  // Can't declare pure virtual functions in sanitizer runtimes:
  // __cxa_pure_virtual might be unavailable.

  // The |stack| parameter is inout. It is pre-filled with the address,
  // module base and module offset values and is to be used to construct
  // other stack frames.
  virtual bool SymbolizePC(uptr addr, SymbolizedStack *stack) {
    UNIMPLEMENTED();
  }

  // The |info| parameter is inout. It is pre-filled with the module base
  // and module offset values.
  virtual bool SymbolizeData(uptr addr, DataInfo *info) {
    UNIMPLEMENTED();
  }

  virtual bool SymbolizeFrame(uptr addr, FrameInfo *info) {
    return false;
  }

  virtual void Flush() {}

  // Return nullptr to fallback to the default platform-specific demangler.
  virtual const char *Demangle(const char *name) {
    return nullptr;
  }

 protected:
  ~SymbolizerTool() {}
};

// SymbolizerProcess encapsulates communication between the tool and
// external symbolizer program, running in a different subprocess.
// SymbolizerProcess may not be used from two threads simultaneously.
class SymbolizerProcess {
 public:
  explicit SymbolizerProcess(const char *path, bool use_posix_spawn = false);
  const char *SendCommand(const char *command);

 protected:
  ~SymbolizerProcess() {}

  /// The maximum number of arguments required to invoke a tool process.
  static const unsigned kArgVMax = 16;

  // Customizable by subclasses.
  virtual bool StartSymbolizerSubprocess();
  virtual bool ReadFromSymbolizer(char *buffer, uptr max_length);
  // // Return the environment to run the symbolizer in.
  virtual char **GetEnvP() { return GetEnviron(); }

 private:
  virtual bool ReachedEndOfOutput(const char *buffer, uptr length) const {
    UNIMPLEMENTED();
  }

  /// Fill in an argv array to invoke the child process.
  virtual void GetArgV(const char *path_to_binary,
                       const char *(&argv)[kArgVMax]) const {
    UNIMPLEMENTED();
  }

  bool Restart();
  const char *SendCommandImpl(const char *command);
  bool WriteToSymbolizer(const char *buffer, uptr length);

  const char *path_;
  fd_t input_fd_;
  fd_t output_fd_;

  static const uptr kBufferSize = 16 * 1024;
  char buffer_[kBufferSize];

  static const uptr kMaxTimesRestarted = 5;
  static const int kSymbolizerStartupTimeMillis = 10;
  uptr times_restarted_;
  bool failed_to_start_;
  bool reported_invalid_path_;
  bool use_posix_spawn_;
};

// For now we assume the following protocol:
// For each request of the form
//   <module_name> <module_offset>
// passed to STDIN, external symbolizer prints to STDOUT response:
//   <function_name>
//   <file_name>:<line_number>:<column_number>
//   <function_name>
//   <file_name>:<line_number>:<column_number>
//   ...
//   <empty line>
class LLVMSymbolizerProcess final : public SymbolizerProcess {
 public:
  explicit LLVMSymbolizerProcess(const char *path)
      : SymbolizerProcess(path, /*use_posix_spawn=*/SANITIZER_MAC) {}

 private:
  bool ReachedEndOfOutput(const char *buffer, uptr length) const override {
    // Empty line marks the end of llvm-symbolizer output.
    return length >= 2 && buffer[length - 1] == '\n' &&
           buffer[length - 2] == '\n';
  }

  // When adding a new architecture, don't forget to also update
  // script/asan_symbolize.py and sanitizer_common.h.
  void GetArgV(const char *path_to_binary,
               const char *(&argv)[kArgVMax]) const override {
#if defined(__x86_64h__)
    const char* const kSymbolizerArch = "--default-arch=x86_64h";
#elif defined(__x86_64__)
    const char* const kSymbolizerArch = "--default-arch=x86_64";
#elif defined(__i386__)
    const char* const kSymbolizerArch = "--default-arch=i386";
#elif SANITIZER_RISCV64
    const char *const kSymbolizerArch = "--default-arch=riscv64";
#elif defined(__aarch64__)
    const char* const kSymbolizerArch = "--default-arch=arm64";
#elif defined(__arm__)
    const char* const kSymbolizerArch = "--default-arch=arm";
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    const char* const kSymbolizerArch = "--default-arch=powerpc64";
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const char* const kSymbolizerArch = "--default-arch=powerpc64le";
#elif defined(__s390x__)
    const char* const kSymbolizerArch = "--default-arch=s390x";
#elif defined(__s390__)
    const char* const kSymbolizerArch = "--default-arch=s390";
#else
    const char* const kSymbolizerArch = "--default-arch=unknown";
#endif

    // const char *const demangle_flag =
    //     common_flags()->demangle ? "--demangle" : "--no-demangle";
    // const char *const inline_flag =
    //     common_flags()->symbolize_inline_frames ? "--inlines" : "--no-inlines";
    const char *const demangle_flag = "--demangle";
    const char *const inline_flag = "--inlines";
    int i = 0;
    argv[i++] = path_to_binary;
    argv[i++] = demangle_flag;
    argv[i++] = inline_flag;
    argv[i++] = kSymbolizerArch;
    argv[i++] = nullptr;
    CHECK_LE(i, kArgVMax);
  }
};

// This tool invokes llvm-symbolizer in a subprocess. It should be as portable
// as the llvm-symbolizer tool is.
class LLVMSymbolizer final : public SymbolizerTool {
 public:
  explicit LLVMSymbolizer(const char *path, LowLevelAllocator *allocator);

  bool SymbolizePC(uptr addr, SymbolizedStack *stack) override;
  bool SymbolizeData(uptr addr, DataInfo *info) override;
  bool SymbolizeFrame(uptr addr, FrameInfo *info) override;

 private:
  const char *FormatAndSendCommand(const char *command_prefix,
                                   const char *module_name, uptr module_offset,
                                   ModuleArch arch);

  LLVMSymbolizerProcess *symbolizer_process_;
  static const uptr kBufferSize = 16 * 1024;
  char buffer_[kBufferSize];
};

LLVMSymbolizer::LLVMSymbolizer(const char *path, LowLevelAllocator *allocator)
  : symbolizer_process_(new(*allocator) LLVMSymbolizerProcess(path)) {}

const char *ExtractToken(const char *str, const char *delims, char **result) {
  uptr prefix_len = std::strcspn(str, delims);
  // *result = (char*)InternalAlloc(prefix_len + 1);
  *result = (char*)malloc(prefix_len + 1);
  std::memcpy(*result, str, prefix_len);
  (*result)[prefix_len] = '\0';
  const char *prefix_end = str + prefix_len;
  if (*prefix_end != '\0') prefix_end++;
  return prefix_end;
}

const char *ExtractUptr(const char *str, const char *delims, uptr *result) {
  char *buff = nullptr;
  const char *ret = ExtractToken(str, delims, &buff);
  if (buff) {
    *result = (uptr)std::atoll(buff);
  }
  // InternalFree(buff);
  free(buff);
  return ret;
}

const char *ExtractSptr(const char *str, const char *delims, sptr *result) {
  char *buff = nullptr;
  const char *ret = ExtractToken(str, delims, &buff);
  if (buff) {
    *result = (sptr)std::atoll(buff);
  }
  // InternalFree(buff);
  free(buff);
  return ret;
}

// Parse a <file>:<line>[:<column>] buffer. The file path may contain colons on
// Windows, so extract tokens from the right hand side first. The column info is
// also optional.
static const char *ParseFileLineInfo(AddressInfo *info, const char *str) {
  char *file_line_info = nullptr;
  str = ExtractToken(str, "\n", &file_line_info);
  CHECK(file_line_info);

  if (uptr size = std::strlen(file_line_info)) {
    char *back = file_line_info + size - 1;
    for (int i = 0; i < 2; ++i) {
      while (back > file_line_info && IsDigit(*back)) --back;
      if (*back != ':' || !IsDigit(back[1])) break;
      info->column = info->line;
      info->line = std::atoll(back + 1);
      // Truncate the string at the colon to keep only filename.
      *back = '\0';
      --back;
    }
    ExtractToken(file_line_info, "", &info->file);
  }

  // InternalFree(file_line_info);
  free(file_line_info);
  return str;
}

// Parses one or more two-line strings in the following format:
//   <function_name>
//   <file_name>:<line_number>[:<column_number>]
// Used by LLVMSymbolizer, Addr2LinePool and InternalSymbolizer, since all of
// them use the same output format.
void ParseSymbolizePCOutput(const char *str, SymbolizedStack *res) {
  bool top_frame = true;
  SymbolizedStack *last = res;
  while (true) {
    char *function_name = nullptr;
    str = ExtractToken(str, "\n", &function_name);
    CHECK(function_name);
    if (function_name[0] == '\0') {
      // There are no more frames.
      // InternalFree(function_name);
      free(function_name);
      break;
    }
    SymbolizedStack *cur;
    if (top_frame) {
      cur = res;
      top_frame = false;
    } else {
      cur = SymbolizedStack::New(res->info.address);
      cur->info.FillModuleInfo(res->info.module, res->info.module_offset,
                               res->info.module_arch);
      last->next = cur;
      last = cur;
    }

    AddressInfo *info = &cur->info;
    info->function = function_name;
    str = ParseFileLineInfo(info, str);

    // Functions and filenames can be "??", in which case we write 0
    // to address info to mark that names are unknown.
    if (0 == std::strcmp(info->function, "??")) {
      // InternalFree(info->function);
      free(info->function);
      info->function = 0;
    }
    if (info->file && 0 == std::strcmp(info->file, "??")) {
      // InternalFree(info->file);
      free(info->file);
      info->file = 0;
    }
  }
}

// Parses a two-line string in the following format:
//   <symbol_name>
//   <start_address> <size>
// Used by LLVMSymbolizer and InternalSymbolizer.
void ParseSymbolizeDataOutput(const char *str, DataInfo *info) {
  str = ExtractToken(str, "\n", &info->name);
  str = ExtractUptr(str, " ", &info->start);
  str = ExtractUptr(str, "\n", &info->size);
}

static void ParseSymbolizeFrameOutput(const char *str,
                                      InternalMmapVector<LocalInfo> *locals) {
  if (std::strncmp(str, "??", 2) == 0)
    return;

  while (*str) {
    LocalInfo local;
    str = ExtractToken(str, "\n", &local.function_name);
    str = ExtractToken(str, "\n", &local.name);

    AddressInfo addr;
    str = ParseFileLineInfo(&addr, str);
    local.decl_file = addr.file;
    local.decl_line = addr.line;

    local.has_frame_offset = std::strncmp(str, "??", 2) != 0;
    str = ExtractSptr(str, " ", &local.frame_offset);

    local.has_size = std::strncmp(str, "??", 2) != 0;
    str = ExtractUptr(str, " ", &local.size);

    local.has_tag_offset = std::strncmp(str, "??", 2) != 0;
    str = ExtractUptr(str, "\n", &local.tag_offset);

    locals->push_back(local);
  }
}

bool LLVMSymbolizer::SymbolizePC(uptr addr, SymbolizedStack *stack) {
  AddressInfo *info = &stack->info;
  const char *buf = FormatAndSendCommand(
      "CODE", info->module, info->module_offset, info->module_arch);
  if (!buf)
    return false;
  ParseSymbolizePCOutput(buf, stack);
  return true;
}

bool LLVMSymbolizer::SymbolizeData(uptr addr, DataInfo *info) {
  const char *buf = FormatAndSendCommand(
      "DATA", info->module, info->module_offset, info->module_arch);
  if (!buf)
    return false;
  ParseSymbolizeDataOutput(buf, info);
  info->start += (addr - info->module_offset); // Add the base address.
  return true;
}

bool LLVMSymbolizer::SymbolizeFrame(uptr addr, FrameInfo *info) {
  const char *buf = FormatAndSendCommand(
      "FRAME", info->module, info->module_offset, info->module_arch);
  if (!buf)
    return false;
  ParseSymbolizeFrameOutput(buf, &info->locals);
  return true;
}

const char *LLVMSymbolizer::FormatAndSendCommand(const char *command_prefix,
                                                 const char *module_name,
                                                 uptr module_offset,
                                                 ModuleArch arch) {
  cilksan_assert(module_name);
  int size_needed = 0;
  if (arch == kModuleArchUnknown)
    size_needed = std::snprintf(buffer_, kBufferSize, "%s \"%s\" 0x%zx\n",
                                command_prefix, module_name, module_offset);
  else
    size_needed = std::snprintf(buffer_, kBufferSize, "%s \"%s:%s\" 0x%zx\n",
                                command_prefix, module_name,
                                ModuleArchToString(arch), module_offset);

  if (size_needed >= static_cast<int>(kBufferSize)) {
    // Report("WARNING: Command buffer too small");
    fprintf(stderr, "LLVMSymbolizer::FormatAndSendCommand: WARNING: Command buffer too small\n");
    return nullptr;
  }

  return symbolizer_process_->SendCommand(buffer_);
}

SymbolizerProcess::SymbolizerProcess(const char *path, bool use_posix_spawn)
    : path_(path),
      input_fd_(kInvalidFd),
      output_fd_(kInvalidFd),
      times_restarted_(0),
      failed_to_start_(false),
      reported_invalid_path_(false),
      use_posix_spawn_(use_posix_spawn) {
  cilksan_assert(path_);
  cilksan_assert(path_[0] != '\0');
}

static bool IsSameModule(const char* path) {
  if (const char* ProcessName = GetProcessName()) {
    if (const char* SymbolizerName = StripModuleName(path)) {
      return !std::strcmp(ProcessName, SymbolizerName);
    }
  }
  return false;
}

const char *SymbolizerProcess::SendCommand(const char *command) {
  if (failed_to_start_)
    return nullptr;
  if (IsSameModule(path_)) {
    // Report("WARNING: Symbolizer was blocked from starting itself!\n");
    fprintf(stderr, "SendCommand: WARNING: Symbolizer was blocked from starting itself!\n");
    failed_to_start_ = true;
    return nullptr;
  }
  for (; times_restarted_ < kMaxTimesRestarted; times_restarted_++) {
    // Start or restart symbolizer if we failed to send command to it.
    if (const char *res = SendCommandImpl(command))
      return res;
    Restart();
  }
  if (!failed_to_start_) {
    // Report("WARNING: Failed to use and restart external symbolizer!\n");
    fprintf(stderr, "SendCommand: WARNING: Failed to use and restart external symbolizer!\n");
    failed_to_start_ = true;
  }
  return nullptr;
}

const char *SymbolizerProcess::SendCommandImpl(const char *command) {
  if (input_fd_ == kInvalidFd || output_fd_ == kInvalidFd)
      return nullptr;
  if (!WriteToSymbolizer(command, std::strlen(command)))
      return nullptr;
  if (!ReadFromSymbolizer(buffer_, kBufferSize))
      return nullptr;
  return buffer_;
}

bool SymbolizerProcess::Restart() {
  if (input_fd_ != kInvalidFd)
    CloseFile(input_fd_);
  if (output_fd_ != kInvalidFd)
    CloseFile(output_fd_);
  return StartSymbolizerSubprocess();
}

bool SymbolizerProcess::ReadFromSymbolizer(char *buffer, uptr max_length) {
  if (max_length == 0)
    return true;
  uptr read_len = 0;
  while (true) {
    uptr just_read = 0;
    bool success = ReadFromFile(input_fd_, buffer + read_len,
                                max_length - read_len - 1, &just_read);
    // We can't read 0 bytes, as we don't expect external symbolizer to close
    // its stdout.
    if (!success || just_read == 0) {
      // Report("WARNING: Can't read from symbolizer at fd %d\n", input_fd_);
      fprintf(
          stderr,
          "ReadFromSymbolizer: WARNING: Can't read from symbolizer at fd %d\n",
          input_fd_);
      return false;
    }
    read_len += just_read;
    if (ReachedEndOfOutput(buffer, read_len))
      break;
    if (read_len + 1 == max_length) {
      // Report("WARNING: Symbolizer buffer too small\n");
      fprintf(stderr, "ReadFromSymbolizer: WARNING: Symbolizer buffer too small\n");
      read_len = 0;
      break;
    }
  }
  buffer[read_len] = '\0';
  return true;
}

bool SymbolizerProcess::WriteToSymbolizer(const char *buffer, uptr length) {
  if (length == 0)
    return true;
  uptr write_len = 0;
  bool success = WriteToFile(output_fd_, buffer, length, &write_len);
  if (!success || write_len != length) {
    // Report("WARNING: Can't write to symbolizer at fd %d\n", output_fd_);
    fprintf(stderr, "WriteToSymbolizer: Can't write to symbolizer at fd %d\n",
            output_fd_);
    return false;
  }
  return true;
}

static bool CreateTwoHighNumberedPipes(int *infd_, int *outfd_) {
  int *infd = NULL;
  int *outfd = NULL;
  // The client program may close its stdin and/or stdout and/or stderr
  // thus allowing socketpair to reuse file descriptors 0, 1 or 2.
  // In this case the communication between the forked processes may be
  // broken if either the parent or the child tries to close or duplicate
  // these descriptors. The loop below produces two pairs of file
  // descriptors, each greater than 2 (stderr).
  int sock_pair[5][2];
  for (int i = 0; i < 5; i++) {
    if (pipe(sock_pair[i]) == -1) {
      for (int j = 0; j < i; j++) {
        close(sock_pair[j][0]);
        close(sock_pair[j][1]);
      }
      return false;
    } else if (sock_pair[i][0] > 2 && sock_pair[i][1] > 2) {
      if (infd == NULL) {
        infd = sock_pair[i];
      } else {
        outfd = sock_pair[i];
        for (int j = 0; j < i; j++) {
          if (sock_pair[j] == infd) continue;
          close(sock_pair[j][0]);
          close(sock_pair[j][1]);
        }
        break;
      }
    }
  }
  CHECK(infd);
  CHECK(outfd);
  infd_[0] = infd[0];
  infd_[1] = infd[1];
  outfd_[0] = outfd[0];
  outfd_[1] = outfd[1];
  return true;
}

bool SymbolizerProcess::StartSymbolizerSubprocess() {
  if (!FileExists(path_)) {
    if (!reported_invalid_path_) {
      // Report("WARNING: invalid path to external symbolizer!\n");
      fprintf(stderr, "StartSymbolizerSubprocess: WARNING: invalid path to "
                      "external symbolizer!\n");
      reported_invalid_path_ = true;
    }
    return false;
  }

  const char *argv[kArgVMax];
  GetArgV(path_, argv);
  pid_t pid;

  // // Report how symbolizer is being launched for debugging purposes.
  // if (Verbosity() >= 3) {
  //   // Only use `Report` for first line so subsequent prints don't get prefixed
  //   // with current PID.
  //   // Report("Launching Symbolizer process: ");
  //   for (unsigned index = 0; index < kArgVMax && argv[index]; ++index)
  //     printf("%s ", argv[index]);
  //   printf("\n");
  // }

  if (use_posix_spawn_) {
#if SANITIZER_MAC
    fd_t fd = internal_spawn(argv, const_cast<const char **>(GetEnvP()), &pid);
    if (fd == kInvalidFd) {
      // Report("WARNING: failed to spawn external symbolizer (errno: %d)\n",
      //        errno);
      fprintf(stderr,
              "StartSymbolizerSubprocess: WARNING: failed to spawn external "
              "symbolizer (errno: %d)\n",
              errno);
      return false;
    }

    input_fd_ = fd;
    output_fd_ = fd;
#else  // SANITIZER_MAC
    UNIMPLEMENTED();
#endif  // SANITIZER_MAC
  } else {
    fd_t infd[2] = {}, outfd[2] = {};
    if (!CreateTwoHighNumberedPipes(infd, outfd)) {
      // Report("WARNING: Can't create a socket pair to start "
      //        "external symbolizer (errno: %d)\n", errno);
      fprintf(stderr,
              "StartSymbolizerSubprocess: WARNING: Can't create a socket pair "
              "to start "
              "external symbolizer (errno: %d)\n",
              errno);
      return false;
    }

    pid = StartSubprocess(path_, argv, GetEnvP(), /* stdin */ outfd[0],
                          /* stdout */ infd[1]);
    if (pid < 0) {
      close(infd[0]);
      close(outfd[1]);
      return false;
    }

    input_fd_ = infd[0];
    output_fd_ = outfd[1];
  }

  CHECK_GT(pid, 0);

  // Check that symbolizer subprocess started successfully.
  SleepForMillis(kSymbolizerStartupTimeMillis);
  if (!IsProcessRunning(pid)) {
    // Either waitpid failed, or child has already exited.
    // Report("WARNING: external symbolizer didn't start up correctly!\n");
    return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////

static const char kPathSeparator = ':';

static char *FindPathToBinary(const char *name) {
  if (FileExists(name)) {
    return strdup(name);
  }

  const char *path = getenv("PATH");
  if (!path)
    return nullptr;
  uptr name_len = std::strlen(name);
  InternalMmapVector<char> buffer(kMaxPathLength);
  const char *beg = path;
  while (true) {
    const char *end = internal_strchrnul(beg, kPathSeparator);
    uptr prefix_len = end - beg;
    if (prefix_len + name_len + 2 <= kMaxPathLength) {
      std::memcpy(buffer.data(), beg, prefix_len);
      buffer[prefix_len] = '/';
      std::memcpy(&buffer[prefix_len + 1], name, name_len);
      buffer[prefix_len + 1 + name_len] = '\0';
      if (FileExists(buffer.data()))
        return strdup(buffer.data());
    }
    if (*end == '\0') break;
    beg = end + 1;
  }
  return nullptr;
}

// Copy the string from "s" to "out", making the following substitutions:
// %b = binary basename
// %p = pid
// %d = binary directory
void SubstituteForFlagValue(const char *s, char *out, uptr out_size) {
  char *out_end = out + out_size;
  while (*s && out < out_end - 1) {
    if (s[0] != '%') {
      *out++ = *s++;
      continue;
    }
    switch (s[1]) {
      case 'b': {
        const char *base = GetProcessName();
        CHECK(base);
        while (*base && out < out_end - 1)
          *out++ = *base++;
        s += 2; // skip "%b"
        break;
      }
      case 'p': {
        int pid = getpid();
        char buf[32];
        char *buf_pos = buf + 32;
        do {
          *--buf_pos = (pid % 10) + '0';
          pid /= 10;
        } while (pid);
        while (buf_pos < buf + 32 && out < out_end - 1)
          *out++ = *buf_pos++;
        s += 2; // skip "%p"
        break;
      }
      case 'd': {
        uptr len = ReadBinaryDir(out, out_end - out);
        out += len;
        s += 2;  // skip "%d"
        break;
      }
      default:
        *out++ = *s++;
        break;
    }
  }
  CHECK(out < out_end - 1);
  *out = '\0';
}

// C++ demangling function, as required by Itanium C++ ABI. This is weak,
// because we do not require a C++ ABI library to be linked to a program
// using sanitizers; if it's not present, we'll just use the mangled name.
namespace __cxxabiv1 {
  extern "C" __attribute__((weak))
  char *__cxa_demangle(const char *mangled, char *buffer,
                                  size_t *length, int *status);
}

// Attempts to demangle the name via __cxa_demangle from __cxxabiv1.
const char *DemangleCXXABI(const char *name) {
  // FIXME: __cxa_demangle aggressively insists on allocating memory.
  // There's not much we can do about that, short of providing our
  // own demangler (libc++abi's implementation could be adapted so that
  // it does not allocate). For now, we just call it anyway, and we leak
  // the returned value.
  if (&__cxxabiv1::__cxa_demangle)
    if (const char *demangled_name =
          __cxxabiv1::__cxa_demangle(name, 0, 0, 0))
      return demangled_name;

  return name;
}

const char *DemangleSwiftAndCXX(const char *name) {
  if (!name) return nullptr;
  // if (const char *swift_demangled_name = DemangleSwift(name))
  //   return swift_demangled_name;
  return DemangleCXXABI(name);
}

const char *Symbolizer::PlatformDemangle(const char *name) {
  return DemangleSwiftAndCXX(name);
}

static SymbolizerTool *ChooseExternalSymbolizer(LowLevelAllocator *allocator) {
  const char *path = getenv("CILKSAN_SYMBOLIZER_PATH");

  if (path && std::strchr(path, '%')) {
    // char *new_path = (char *)InternalAlloc(kMaxPathLength);
    char *new_path = (char *)malloc(kMaxPathLength);
    SubstituteForFlagValue(path, new_path, kMaxPathLength);
    path = new_path;
  }

  const char *binary_name = path ? StripModuleName(path) : "";
  static const char kLLVMSymbolizerPrefix[] = "llvm-symbolizer";

  // If an external symbolizer path is given, use it.
  if (path && path[0] == '\0') {
    return nullptr;
  } else if (!std::strncmp(binary_name, kLLVMSymbolizerPrefix,
                           std::strlen(kLLVMSymbolizerPrefix))) {
    return new LLVMSymbolizer(path, allocator);
  } else if (path) {
    cilksan_assert(false &&
                   "ERROR: External symbolizer path isn't a known symbolizer.");
  }

  // Otherwise search $PATH for symbolizer.
  if (const char *found_path = FindPathToBinary("llvm-symbolizer")) {
    return new LLVMSymbolizer(found_path, allocator);
  }

  return nullptr;
}

static void ChooseSymbolizerTools(IntrusiveList<SymbolizerTool> *list,
                                  LowLevelAllocator *allocator) {
  // if (!common_flags()->symbolize) {
  //   VReport(2, "Symbolizer is disabled.\n");
  //   return;
  // }
  // if (IsAllocatorOutOfMemory()) {
  //   VReport(2, "Cannot use internal symbolizer: out of memory\n");
  // } else if (SymbolizerTool *tool = InternalSymbolizer::get(allocator)) {
  //   VReport(2, "Using internal symbolizer.\n");
  //   list->push_back(tool);
  //   return;
  // }
  // if (SymbolizerTool *tool = LibbacktraceSymbolizer::get(allocator)) {
  //   VReport(2, "Using libbacktrace symbolizer.\n");
  //   list->push_back(tool);
  //   return;
  // }

  if (SymbolizerTool *tool = ChooseExternalSymbolizer(allocator)) {
    list->push_back(tool);
  }

// #if SANITIZER_MAC
//   VReport(2, "Using dladdr symbolizer.\n");
//   list->push_back(new(*allocator) DlAddrSymbolizer());
// #endif  // SANITIZER_MAC
}

Symbolizer *Symbolizer::symbolizer_;
std::mutex Symbolizer::init_mu_;
LowLevelAllocator Symbolizer::symbolizer_allocator_;

const char *Symbolizer::ModuleNameOwner::GetOwnedCopy(const char *str) {
  // mu_->CheckLocked();

  // 'str' will be the same string multiple times in a row, optimize this case.
  if (last_match_ && !strcmp(last_match_, str))
    return last_match_;

  // FIXME: this is linear search.
  // We should optimize this further if this turns out to be a bottleneck later.
  for (uptr i = 0; i < storage_.size(); ++i) {
    if (!strcmp(storage_[i], str)) {
      last_match_ = storage_[i];
      return last_match_;
    }
  }
  last_match_ = strdup(str);
  storage_.push_back(last_match_);
  return last_match_;
}

Symbolizer::Symbolizer(IntrusiveList<SymbolizerTool> tools)
    : module_names_(&mu_), modules_(), modules_fresh_(false), tools_(tools),
      start_hook_(0), end_hook_(0) {}

Symbolizer::SymbolizerScope::SymbolizerScope(const Symbolizer *sym)
    : sym_(sym) {
  if (sym_->start_hook_)
    sym_->start_hook_();
}

Symbolizer::SymbolizerScope::~SymbolizerScope() {
  if (sym_->end_hook_)
    sym_->end_hook_();
}

Symbolizer *Symbolizer::PlatformInit() {
  IntrusiveList<SymbolizerTool> list;
  list.clear();
  ChooseSymbolizerTools(&list, &symbolizer_allocator_);
  return new(symbolizer_allocator_) Symbolizer(list);
}

Symbolizer *Symbolizer::GetOrInit() {
  std::lock_guard<std::mutex> l(init_mu_);
  if (symbolizer_)
    return symbolizer_;
  symbolizer_ = PlatformInit();
  CHECK(symbolizer_);
  return symbolizer_;
}

SymbolizedStack *Symbolizer::SymbolizePC(uptr addr) {
  // Lock l(&mu_);
  std::lock_guard<std::mutex> l(mu_);
  SymbolizedStack *res = SymbolizedStack::New(addr);
  auto *mod = FindModuleForAddress(addr);
  if (!mod)
    return res;
  // Always fill data about module name and offset.
  res->info.FillModuleInfo(*mod);
  for (auto &tool : tools_) {
    SymbolizerScope sym_scope(this);
    if (tool.SymbolizePC(addr, res)) {
      return res;
    }
  }
  return res;
}

bool Symbolizer::SymbolizeData(uptr addr, DataInfo *info) {
  // Lock l(&mu_);
  std::lock_guard<std::mutex> l(mu_);
  const char *module_name = nullptr;
  uptr module_offset;
  ModuleArch arch;
  if (!FindModuleNameAndOffsetForAddress(addr, &module_name, &module_offset,
                                         &arch))
    return false;
  info->Clear();
  info->module = strdup(module_name);
  info->module_offset = module_offset;
  info->module_arch = arch;
  for (auto &tool : tools_) {
    SymbolizerScope sym_scope(this);
    if (tool.SymbolizeData(addr, info)) {
      return true;
    }
  }
  return true;
}

bool Symbolizer::SymbolizeFrame(uptr addr, FrameInfo *info) {
  // Lock l(&mu_);
  std::lock_guard<std::mutex> l(mu_);
  const char *module_name = nullptr;
  if (!FindModuleNameAndOffsetForAddress(
          addr, &module_name, &info->module_offset, &info->module_arch))
    return false;
  info->module = strdup(module_name);
  for (auto &tool : tools_) {
    SymbolizerScope sym_scope(this);
    if (tool.SymbolizeFrame(addr, info)) {
      return true;
    }
  }
  return true;
}

bool Symbolizer::GetModuleNameAndOffsetForPC(uptr pc, const char **module_name,
                                             uptr *module_address) {
  // Lock l(&mu_);
  std::lock_guard<std::mutex> l(mu_);
  const char *internal_module_name = nullptr;
  ModuleArch arch;
  if (!FindModuleNameAndOffsetForAddress(pc, &internal_module_name,
                                         module_address, &arch))
    return false;

  if (module_name)
    *module_name = module_names_.GetOwnedCopy(internal_module_name);
  return true;
}

void Symbolizer::Flush() {
  // Lock l(&mu_);
  std::lock_guard<std::mutex> l(mu_);
  for (auto &tool : tools_) {
    SymbolizerScope sym_scope(this);
    tool.Flush();
  }
}

const char *Symbolizer::Demangle(const char *name) {
  // Lock l(&mu_);
  std::lock_guard<std::mutex> l(mu_);
  for (auto &tool : tools_) {
    SymbolizerScope sym_scope(this);
    if (const char *demangled = tool.Demangle(name))
      return demangled;
  }
  return PlatformDemangle(name);
}

bool Symbolizer::FindModuleNameAndOffsetForAddress(uptr address,
                                                   const char **module_name,
                                                   uptr *module_offset,
                                                   ModuleArch *module_arch) {
  const LoadedModule *module = FindModuleForAddress(address);
  if (!module)
    return false;
  *module_name = module->full_name();
  *module_offset = address - module->base_address();
  *module_arch = module->arch();
  return true;
}

void Symbolizer::RefreshModules() {
  modules_.init();
  fallback_modules_.fallbackInit();
  // RAW_CHECK(modules_.size() > 0);
  CHECK(modules_.size() > 0);
  modules_fresh_ = true;
}

static const LoadedModule *SearchForModule(const ListOfModules &modules,
                                           uptr address) {
  for (uptr i = 0; i < modules.size(); i++) {
    if (modules[i].containsAddress(address)) {
      return &modules[i];
    }
  }
  return nullptr;
}

const LoadedModule *Symbolizer::FindModuleForAddress(uptr address) {
  bool modules_were_reloaded = false;
  if (!modules_fresh_) {
    RefreshModules();
    modules_were_reloaded = true;
  }
  const LoadedModule *module = SearchForModule(modules_, address);
  if (module) return module;

  // dlopen/dlclose interceptors invalidate the module list, but when
  // interception is disabled, we need to retry if the lookup fails in
  // case the module list changed.
#if !SANITIZER_INTERCEPT_DLOPEN_DLCLOSE
  if (!modules_were_reloaded) {
    RefreshModules();
    module = SearchForModule(modules_, address);
    if (module) return module;
  }
#endif

  if (fallback_modules_.size()) {
    module = SearchForModule(fallback_modules_, address);
  }
  return module;
}
