#include "symbolizer.h"

#include <fcntl.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#if SANITIZER_MAC
#include "symbolizer_mac.h"

#include <crt_externs.h> // for _NSGetArgv and _NSGetEnviron

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#elif SANITIZER_LINUX
#include "symbolizer_linux.h"

#include <link.h>
#include <linux/sysctl.h>
#endif

#if SANITIZER_MAC
char **GetEnviron() {
  char ***env_ptr = _NSGetEnviron();
  if (!env_ptr) {
    // Report("_NSGetEnviron() returned NULL. Please make sure __asan_init() is "
    //        "called after libSystem_initializer().\n");
    CHECK(env_ptr);
  }
  char **environ = *env_ptr;
  CHECK(environ);
  return environ;
}

uptr ReadBinaryName(/*out*/char *buf, uptr buf_len) {
  CHECK_LE(kMaxPathLength, buf_len);

  // On OS X the executable path is saved to the stack by dyld. Reading it
  // from there is much faster than calling dladdr, especially for large
  // binaries with symbols.
  InternalMmapVector<char> exe_path(kMaxPathLength);
  uint32_t size = exe_path.size();
  if (_NSGetExecutablePath(exe_path.data(), &size) == 0 &&
      realpath(exe_path.data(), buf) != 0) {
    return std::strlen(buf);
  }
  return 0;
}

uptr ReadLongProcessName(/*out*/char *buf, uptr buf_len) {
  return ReadBinaryName(buf, buf_len);
}

#else // SANITIZER_MAC

uptr ReadBinaryName(/*out*/char *buf, uptr buf_len) {
#if SANITIZER_FREEBSD || SANITIZER_NETBSD
#if SANITIZER_FREEBSD
  const int Mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
#else
  const int Mib[4] = {CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME};
#endif
  const char *default_module_name = "kern.proc.pathname";
  uptr Size = buf_len;
  bool IsErr = (sysctl(Mib, ARRAY_SIZE(Mib), buf, &Size, NULL, 0) != 0);
  int readlink_error = IsErr ? errno : 0;
  uptr module_name_len = Size;
#else
  const char *default_module_name = "/proc/self/exe";
  uptr module_name_len = readlink(default_module_name, buf, buf_len);
  int readlink_error;
  bool IsErr = internal_iserror(module_name_len, &readlink_error);
#endif
  if (IsErr) {
    // We can't read binary name for some reason, assume it's unknown.
    // Report("WARNING: reading executable name failed with errno %d, "
    //        "some stack frames may not be symbolized\n", readlink_error);
    fprintf(stderr,
            "WARNING: reading executable name failed with errno %d, "
            "some stack frames may not be symbolized\n",
            readlink_error);
    module_name_len = std::snprintf(buf, buf_len, "%s", default_module_name);
    CHECK_LT(module_name_len, buf_len);
  }
  return module_name_len;
}

uptr ReadLongProcessName(/*out*/ char *buf, uptr buf_len) {
#if SANITIZER_LINUX
  char *tmpbuf;
  uptr tmpsize;
  uptr tmplen;
  if (ReadFileToBuffer("/proc/self/cmdline", &tmpbuf, &tmpsize, &tmplen,
                       1024 * 1024)) {
    std::strncpy(buf, tmpbuf, buf_len);
    UnmapOrDie(tmpbuf, tmpsize);
    return std::strlen(buf);
  }
#endif
  return ReadBinaryName(buf, buf_len);
}

#if !SANITIZER_FREEBSD
extern "C" {
__attribute__((weak)) extern void *__libc_stack_end;
}

static void ReadNullSepFileToArray(const char *path, char ***arr,
                                   int arr_size) {
  char *buff;
  uptr buff_size;
  uptr buff_len;
  *arr = (char **)MmapOrDie(arr_size * sizeof(char *), "NullSepFileArray");
  if (!ReadFileToBuffer(path, &buff, &buff_size, &buff_len, 1024 * 1024)) {
    (*arr)[0] = nullptr;
    return;
  }
  (*arr)[0] = buff;
  int count, i;
  for (count = 1, i = 1; ; i++) {
    if (buff[i] == 0) {
      if (buff[i+1] == 0) break;
      (*arr)[count] = &buff[i+1];
      CHECK_LE(count, arr_size - 1);  // FIXME: make this more flexible.
      count++;
    }
  }
  (*arr)[count] = nullptr;
}
#endif // !SANITIZER_FREEBSD

static void GetArgsAndEnv(char ***argv, char ***envp) {
#if SANITIZER_FREEBSD
  // On FreeBSD, retrieving the argument and environment arrays is done via the
  // kern.ps_strings sysctl, which returns a pointer to a structure containing
  // this information. See also <sys/exec.h>.
  ps_strings *pss;
  uptr sz = sizeof(pss);
  if (internal_sysctlbyname("kern.ps_strings", &pss, &sz, NULL, 0) == -1) {
    Printf("sysctl kern.ps_strings failed\n");
    Die();
  }
  *argv = pss->ps_argvstr;
  *envp = pss->ps_envstr;
#else // SANITIZER_FREEBSD
  if (&__libc_stack_end) {
    uptr* stack_end = (uptr*)__libc_stack_end;
    // Normally argc can be obtained from *stack_end, however, on ARM glibc's
    // _start clobbers it:
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/arm/start.S;hb=refs/heads/release/2.31/master#l75
    // Do not special-case ARM and infer argc from argv everywhere.
    int argc = 0;
    while (stack_end[argc + 1]) argc++;
    *argv = (char**)(stack_end + 1);
    *envp = (char**)(stack_end + argc + 2);
  } else {
    static const int kMaxArgv = 2000, kMaxEnvp = 2000;
    ReadNullSepFileToArray("/proc/self/cmdline", argv, kMaxArgv);
    ReadNullSepFileToArray("/proc/self/environ", envp, kMaxEnvp);
  }
#endif // SANITIZER_FREEBSD
}

char **GetEnviron() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return envp;
}
#endif // SANITIZER_MAC

///////////////////////////////////////////////////////////////////////////

#if SANITIZER_MAC
template <typename Section>
static void NextSectionLoad(LoadedModule *module, MemoryMappedSegmentData *data,
                            bool isWritable) {
  const Section *sc = (const Section *)data->current_load_cmd_addr;
  data->current_load_cmd_addr += sizeof(Section);

  uptr sec_start = (sc->addr & data->addr_mask) + data->base_virt_addr;
  uptr sec_end = sec_start + sc->size;
  module->addAddressRange(sec_start, sec_end, /*executable=*/false, isWritable,
                          sc->sectname);
}

void MemoryMappedSegment::AddAddressRanges(LoadedModule *module) {
  // Don't iterate over sections when the caller hasn't set up the
  // data pointer, when there are no sections, or when the segment
  // is executable. Avoid iterating over executable sections because
  // it will confuse libignore, and because the extra granularity
  // of information is not needed by any sanitizers.
  if (!data_ || !data_->nsects || IsExecutable()) {
    module->addAddressRange(start, end, IsExecutable(), IsWritable(),
                            data_ ? data_->name : nullptr);
    return;
  }

  do {
    if (data_->lc_type == LC_SEGMENT) {
      NextSectionLoad<struct section>(module, data_, IsWritable());
#ifdef MH_MAGIC_64
    } else if (data_->lc_type == LC_SEGMENT_64) {
      NextSectionLoad<struct section_64>(module, data_, IsWritable());
#endif
    }
  } while (--data_->nsects);
}

// More information about Mach-O headers can be found in mach-o/loader.h
// Each Mach-O image has a header (mach_header or mach_header_64) starting with
// a magic number, and a list of linker load commands directly following the
// header.
// A load command is at least two 32-bit words: the command type and the
// command size in bytes. We're interested only in segment load commands
// (LC_SEGMENT and LC_SEGMENT_64), which tell that a part of the file is mapped
// into the task's address space.
// The |vmaddr|, |vmsize| and |fileoff| fields of segment_command or
// segment_command_64 correspond to the memory address, memory size and the
// file offset of the current memory segment.
// Because these fields are taken from the images as is, one needs to add
// _dyld_get_image_vmaddr_slide() to get the actual addresses at runtime.

void MemoryMappingLayout::Reset() {
  // Count down from the top.
  // TODO(glider): as per man 3 dyld, iterating over the headers with
  // _dyld_image_count is thread-unsafe. We need to register callbacks for
  // adding and removing images which will invalidate the MemoryMappingLayout
  // state.
  data_.current_image = _dyld_image_count();
  data_.current_load_cmd_count = -1;
  data_.current_load_cmd_addr = 0;
  data_.current_magic = 0;
  data_.current_filetype = 0;
  data_.current_arch = kModuleArchUnknown;
  std::memset(data_.current_uuid, 0, kModuleUUIDSize);
}

// static
void MemoryMappingLayout::CacheMemoryMappings() {
  // No-op on Mac for now.
}

void MemoryMappingLayout::LoadFromCache() {
  // No-op on Mac for now.
}

MemoryMappingLayout::MemoryMappingLayout(bool cache_enabled) {
  Reset();
}

MemoryMappingLayout::~MemoryMappingLayout() {
}

bool MemoryMappingLayout::Error() const {
  return false;
}

void MemoryMappingLayout::DumpListOfModules(
    InternalMmapVectorNoCtor<LoadedModule> *modules) {
  Reset();
  InternalMmapVector<char> module_name(kMaxPathLength);
  MemoryMappedSegment segment(module_name.data(), module_name.size());
  MemoryMappedSegmentData data;
  segment.data_ = &data;
  while (Next(&segment)) {
    if (segment.filename[0] == '\0') continue;
    LoadedModule *cur_module = nullptr;
    if (!modules->empty() &&
        0 == std::strcmp(segment.filename, modules->back().full_name())) {
      cur_module = &modules->back();
    } else {
      modules->push_back(LoadedModule());
      cur_module = &modules->back();
      cur_module->set(segment.filename, segment.start, segment.arch,
                      segment.uuid, data_.current_instrumented);
    }
    segment.AddAddressRanges(cur_module);
  }
}

// The dyld load address should be unchanged throughout process execution,
// and it is expensive to compute once many libraries have been loaded,
// so cache it here and do not reset.
static mach_header *dyld_hdr = 0;
static const char kDyldPath[] = "/usr/lib/dyld";
static const int kDyldImageIdx = -1;

// _dyld_get_image_header() and related APIs don't report dyld itself.
// We work around this by manually recursing through the memory map
// until we hit a Mach header matching dyld instead. These recurse
// calls are expensive, but the first memory map generation occurs
// early in the process, when dyld is one of the only images loaded,
// so it will be hit after only a few iterations.
static mach_header *get_dyld_image_header() {
  vm_address_t address = 0;

  while (true) {
    vm_size_t size = 0;
    unsigned depth = 1;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t err =
        vm_region_recurse_64(mach_task_self(), &address, &size, &depth,
                             (vm_region_info_t)&info, &count);
    if (err != KERN_SUCCESS) return nullptr;

    if (size >= sizeof(mach_header) && info.protection & kProtectionRead) {
      mach_header *hdr = (mach_header *)address;
      if ((hdr->magic == MH_MAGIC || hdr->magic == MH_MAGIC_64) &&
          hdr->filetype == MH_DYLINKER) {
        return hdr;
      }
    }
    address += size;
  }
}

const mach_header *get_dyld_hdr() {
  if (!dyld_hdr) dyld_hdr = get_dyld_image_header();

  return dyld_hdr;
}

// Next and NextSegmentLoad were inspired by base/sysinfo.cc in
// Google Perftools, https://github.com/gperftools/gperftools.

// NextSegmentLoad scans the current image for the next segment load command
// and returns the start and end addresses and file offset of the corresponding
// segment.
// Note that the segment addresses are not necessarily sorted.
template <u32 kLCSegment, typename SegmentCommand>
static bool NextSegmentLoad(MemoryMappedSegment *segment,
                            MemoryMappedSegmentData *seg_data,
                            MemoryMappingLayoutData *layout_data) {
  const char *lc = layout_data->current_load_cmd_addr;
  layout_data->current_load_cmd_addr += ((const load_command *)lc)->cmdsize;
  if (((const load_command *)lc)->cmd == kLCSegment) {
    const SegmentCommand* sc = (const SegmentCommand *)lc;
    uptr base_virt_addr, addr_mask;
    if (layout_data->current_image == kDyldImageIdx) {
      base_virt_addr = (uptr)get_dyld_hdr();
      // vmaddr is masked with 0xfffff because on macOS versions < 10.12,
      // it contains an absolute address rather than an offset for dyld.
      // To make matters even more complicated, this absolute address
      // isn't actually the absolute segment address, but the offset portion
      // of the address is accurate when combined with the dyld base address,
      // and the mask will give just this offset.
      addr_mask = 0xfffff;
    } else {
      base_virt_addr =
          (uptr)_dyld_get_image_vmaddr_slide(layout_data->current_image);
      addr_mask = ~0;
    }

    segment->start = (sc->vmaddr & addr_mask) + base_virt_addr;
    segment->end = segment->start + sc->vmsize;
    // Most callers don't need section information, so only fill this struct
    // when required.
    if (seg_data) {
      seg_data->nsects = sc->nsects;
      seg_data->current_load_cmd_addr =
          (const char *)lc + sizeof(SegmentCommand);
      seg_data->lc_type = kLCSegment;
      seg_data->base_virt_addr = base_virt_addr;
      seg_data->addr_mask = addr_mask;
      std::strncpy(seg_data->name, sc->segname,
                       ARRAY_SIZE(seg_data->name));
    }

    // Return the initial protection.
    segment->protection = sc->initprot;
    segment->offset = (layout_data->current_filetype ==
                       /*MH_EXECUTE*/ 0x2)
                          ? sc->vmaddr
                          : sc->fileoff;
    if (segment->filename) {
      const char *src = (layout_data->current_image == kDyldImageIdx)
                            ? kDyldPath
                            : _dyld_get_image_name(layout_data->current_image);
      std::strncpy(segment->filename, src, segment->filename_size);
    }
    segment->arch = layout_data->current_arch;
    std::memcpy(segment->uuid, layout_data->current_uuid, kModuleUUIDSize);
    return true;
  }
  return false;
}

ModuleArch ModuleArchFromCpuType(cpu_type_t cputype, cpu_subtype_t cpusubtype) {
  cpusubtype = cpusubtype & ~CPU_SUBTYPE_MASK;
  switch (cputype) {
    case CPU_TYPE_I386:
      return kModuleArchI386;
    case CPU_TYPE_X86_64:
      if (cpusubtype == CPU_SUBTYPE_X86_64_ALL) return kModuleArchX86_64;
      if (cpusubtype == CPU_SUBTYPE_X86_64_H) return kModuleArchX86_64H;
      CHECK(0 && "Invalid subtype of x86_64");
      return kModuleArchUnknown;
    case CPU_TYPE_ARM:
      if (cpusubtype == CPU_SUBTYPE_ARM_V6) return kModuleArchARMV6;
      if (cpusubtype == CPU_SUBTYPE_ARM_V7) return kModuleArchARMV7;
      if (cpusubtype == CPU_SUBTYPE_ARM_V7S) return kModuleArchARMV7S;
      if (cpusubtype == CPU_SUBTYPE_ARM_V7K) return kModuleArchARMV7K;
      CHECK(0 && "Invalid subtype of ARM");
      return kModuleArchUnknown;
    case CPU_TYPE_ARM64:
      return kModuleArchARM64;
    default:
      CHECK(0 && "Invalid CPU type");
      return kModuleArchUnknown;
  }
}

static const load_command *NextCommand(const load_command *lc) {
  return (const load_command *)((const char *)lc + lc->cmdsize);
}

static void FindUUID(const load_command *first_lc, u8 *uuid_output) {
  for (const load_command *lc = first_lc; lc->cmd != 0; lc = NextCommand(lc)) {
    if (lc->cmd != LC_UUID) continue;

    const uuid_command *uuid_lc = (const uuid_command *)lc;
    const uint8_t *uuid = &uuid_lc->uuid[0];
    std::memcpy(uuid_output, uuid, kModuleUUIDSize);
    return;
  }
}

static bool IsModuleInstrumented(const load_command *first_lc) {
  for (const load_command *lc = first_lc; lc->cmd != 0; lc = NextCommand(lc)) {
    if (lc->cmd != LC_LOAD_DYLIB) continue;

    const dylib_command *dylib_lc = (const dylib_command *)lc;
    uint32_t dylib_name_offset = dylib_lc->dylib.name.offset;
    const char *dylib_name = ((const char *)dylib_lc) + dylib_name_offset;
    dylib_name = StripModuleName(dylib_name);
    if (dylib_name != 0 && (std::strstr(dylib_name, "libclang_rt."))) {
      return true;
    }
  }
  return false;
}

bool MemoryMappingLayout::Next(MemoryMappedSegment *segment) {
  for (; data_.current_image >= kDyldImageIdx; data_.current_image--) {
    const mach_header *hdr = (data_.current_image == kDyldImageIdx)
                                 ? get_dyld_hdr()
                                 : _dyld_get_image_header(data_.current_image);
    if (!hdr) continue;
    if (data_.current_load_cmd_count < 0) {
      // Set up for this image;
      data_.current_load_cmd_count = hdr->ncmds;
      data_.current_magic = hdr->magic;
      data_.current_filetype = hdr->filetype;
      data_.current_arch = ModuleArchFromCpuType(hdr->cputype, hdr->cpusubtype);
      switch (data_.current_magic) {
#ifdef MH_MAGIC_64
        case MH_MAGIC_64: {
          data_.current_load_cmd_addr =
              (const char *)hdr + sizeof(mach_header_64);
          break;
        }
#endif
        case MH_MAGIC: {
          data_.current_load_cmd_addr = (const char *)hdr + sizeof(mach_header);
          break;
        }
        default: {
          continue;
        }
      }
      FindUUID((const load_command *)data_.current_load_cmd_addr,
               data_.current_uuid);
      data_.current_instrumented = IsModuleInstrumented(
          (const load_command *)data_.current_load_cmd_addr);
    }

    for (; data_.current_load_cmd_count >= 0; data_.current_load_cmd_count--) {
      switch (data_.current_magic) {
        // data_.current_magic may be only one of MH_MAGIC, MH_MAGIC_64.
#ifdef MH_MAGIC_64
        case MH_MAGIC_64: {
          if (NextSegmentLoad<LC_SEGMENT_64, struct segment_command_64>(
                  segment, segment->data_, &data_))
            return true;
          break;
        }
#endif
        case MH_MAGIC: {
          if (NextSegmentLoad<LC_SEGMENT, struct segment_command>(
                  segment, segment->data_, &data_))
            return true;
          break;
        }
      }
    }
    // If we get here, no more load_cmd's in this image talk about
    // segments.  Go on to the next image.
  }
  return false;
}

static fd_t internal_spawn_impl(const char *argv[], const char *envp[],
                                pid_t *pid) {
  fd_t primary_fd = kInvalidFd;
  fd_t secondary_fd = kInvalidFd;

  auto fd_closer = at_scope_exit([&] {
    close(primary_fd);
    close(secondary_fd);
  });

  // We need a new pseudoterminal to avoid buffering problems. The 'atos' tool
  // in particular detects when it's talking to a pipe and forgets to flush the
  // output stream after sending a response.
  primary_fd = posix_openpt(O_RDWR);
  if (primary_fd == kInvalidFd)
    return kInvalidFd;

  int res = grantpt(primary_fd) || unlockpt(primary_fd);
  if (res != 0) return kInvalidFd;

  // Use TIOCPTYGNAME instead of ptsname() to avoid threading problems.
  char secondary_pty_name[128];
  res = ioctl(primary_fd, TIOCPTYGNAME, secondary_pty_name);
  if (res == -1) return kInvalidFd;

  secondary_fd = open(secondary_pty_name, O_RDWR);
  if (secondary_fd == kInvalidFd)
    return kInvalidFd;

  // File descriptor actions
  posix_spawn_file_actions_t acts;
  res = posix_spawn_file_actions_init(&acts);
  if (res != 0) return kInvalidFd;

  auto acts_cleanup = at_scope_exit([&] {
    posix_spawn_file_actions_destroy(&acts);
  });

  res = posix_spawn_file_actions_adddup2(&acts, secondary_fd, STDIN_FILENO) ||
        posix_spawn_file_actions_adddup2(&acts, secondary_fd, STDOUT_FILENO) ||
        posix_spawn_file_actions_addclose(&acts, secondary_fd);
  if (res != 0) return kInvalidFd;

  // Spawn attributes
  posix_spawnattr_t attrs;
  res = posix_spawnattr_init(&attrs);
  if (res != 0) return kInvalidFd;

  auto attrs_cleanup  = at_scope_exit([&] {
    posix_spawnattr_destroy(&attrs);
  });

  // In the spawned process, close all file descriptors that are not explicitly
  // described by the file actions object. This is Darwin-specific extension.
  res = posix_spawnattr_setflags(&attrs, POSIX_SPAWN_CLOEXEC_DEFAULT);
  if (res != 0) return kInvalidFd;

  // posix_spawn
  char **argv_casted = const_cast<char **>(argv);
  char **envp_casted = const_cast<char **>(envp);
  res = posix_spawn(pid, argv[0], &acts, &attrs, argv_casted, envp_casted);
  if (res != 0) return kInvalidFd;

  // Disable echo in the new terminal, disable CR.
  struct termios termflags;
  tcgetattr(primary_fd, &termflags);
  termflags.c_oflag &= ~ONLCR;
  termflags.c_lflag &= ~ECHO;
  tcsetattr(primary_fd, TCSANOW, &termflags);

  // On success, do not close primary_fd on scope exit.
  fd_t fd = primary_fd;
  primary_fd = kInvalidFd;

  return fd;
}

fd_t internal_spawn(const char *argv[], const char *envp[], pid_t *pid) {
  // The client program may close its stdin and/or stdout and/or stderr thus
  // allowing open/posix_openpt to reuse file descriptors 0, 1 or 2. In this
  // case the communication is broken if either the parent or the child tries to
  // close or duplicate these descriptors. We temporarily reserve these
  // descriptors here to prevent this.
  fd_t low_fds[3];
  size_t count = 0;

  for (; count < 3; count++) {
    low_fds[count] = posix_openpt(O_RDWR);
    if (low_fds[count] >= STDERR_FILENO)
      break;
  }

  fd_t fd = internal_spawn_impl(argv, envp, pid);

  for (; count > 0; count--) {
    close(low_fds[count]);
  }

  return fd;
}

void ListOfModules::init() {
  clearOrInit();
  MemoryMappingLayout memory_mapping(false);
  memory_mapping.DumpListOfModules(&modules_);
}

void ListOfModules::fallbackInit() { clear(); }

#else // SANITIZER_MAC

#if !SANITIZER_FREEBSD
typedef ElfW(Phdr) Elf_Phdr;
#elif SANITIZER_WORDSIZE == 32 && __FreeBSD_version <= 902001  // v9.2
#define Elf_Phdr XElf32_Phdr
#define dl_phdr_info xdl_phdr_info
#define dl_iterate_phdr(c, b) xdl_iterate_phdr((c), (b))
#endif  // !SANITIZER_FREEBSD

struct DlIteratePhdrData {
  InternalMmapVectorNoCtor<LoadedModule> *modules;
  bool first;
};

static int AddModuleSegments(const char *module_name, dl_phdr_info *info,
                             InternalMmapVectorNoCtor<LoadedModule> *modules) {
  if (module_name[0] == '\0')
    return 0;
  LoadedModule cur_module;
  cur_module.set(module_name, info->dlpi_addr);
  for (int i = 0; i < (int)info->dlpi_phnum; i++) {
    const Elf_Phdr *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type == PT_LOAD) {
      uptr cur_beg = info->dlpi_addr + phdr->p_vaddr;
      uptr cur_end = cur_beg + phdr->p_memsz;
      bool executable = phdr->p_flags & PF_X;
      bool writable = phdr->p_flags & PF_W;
      cur_module.addAddressRange(cur_beg, cur_end, executable,
                                 writable);
    } else if (phdr->p_type == PT_NOTE) {
#  ifdef NT_GNU_BUILD_ID
      uptr off = 0;
      while (off + sizeof(ElfW(Nhdr)) < phdr->p_memsz) {
        auto *nhdr = reinterpret_cast<const ElfW(Nhdr) *>(info->dlpi_addr +
                                                          phdr->p_vaddr + off);
        constexpr auto kGnuNamesz = 4;  // "GNU" with NUL-byte.
        static_assert(kGnuNamesz % 4 == 0, "kGnuNameSize is aligned to 4.");
        if (nhdr->n_type == NT_GNU_BUILD_ID && nhdr->n_namesz == kGnuNamesz) {
          if (off + sizeof(ElfW(Nhdr)) + nhdr->n_namesz + nhdr->n_descsz >
              phdr->p_memsz) {
            // Something is very wrong, bail out instead of reading potentially
            // arbitrary memory.
            break;
          }
          const char *name =
              reinterpret_cast<const char *>(nhdr) + sizeof(*nhdr);
          if (std::memcmp(name, "GNU", 3) == 0) {
            const char *value = reinterpret_cast<const char *>(nhdr) +
                                sizeof(*nhdr) + kGnuNamesz;
            cur_module.setUuid(value, nhdr->n_descsz);
            break;
          }
        }
        off += sizeof(*nhdr) + RoundUpTo(nhdr->n_namesz, 4) +
               RoundUpTo(nhdr->n_descsz, 4);
      }
#  endif
    }
  }
  modules->push_back(cur_module);
  return 0;
}

static int dl_iterate_phdr_cb(dl_phdr_info *info, size_t size, void *arg) {
  DlIteratePhdrData *data = (DlIteratePhdrData *)arg;
  if (data->first) {
    InternalMmapVector<char> module_name(kMaxPathLength);
    data->first = false;
    // First module is the binary itself.
    ReadBinaryNameCached(module_name.data(), module_name.size());
    return AddModuleSegments(module_name.data(), info, data->modules);
  }

  if (info->dlpi_name) {
    InternalScopedString module_name;
    module_name.append("%s", info->dlpi_name);
    return AddModuleSegments(module_name.data(), info, data->modules);
  }

  return 0;
}

static bool requiresProcmaps() {
  return false;
}

static void procmapsInit(InternalMmapVectorNoCtor<LoadedModule> *modules) {
  MemoryMappingLayout memory_mapping(/*cache_enabled*/true);
  memory_mapping.DumpListOfModules(modules);
}

void ListOfModules::init() {
  clearOrInit();
  if (requiresProcmaps()) {
    procmapsInit(&modules_);
  } else {
    DlIteratePhdrData data = {&modules_, true};
    dl_iterate_phdr(dl_iterate_phdr_cb, &data);
  }
}

// When a custom loader is used, dl_iterate_phdr may not contain the full
// list of modules. Allow callers to fall back to using procmaps.
void ListOfModules::fallbackInit() {
  if (!requiresProcmaps()) {
    clearOrInit();
    procmapsInit(&modules_);
  } else {
    clear();
  }
}

static ProcSelfMapsBuff cached_proc_self_maps;
static std::mutex cache_lock;

static void ReadProcMaps(ProcSelfMapsBuff *proc_maps) {
  if (!ReadFileToBuffer("/proc/self/maps", &proc_maps->data,
                        &proc_maps->mmaped_size, &proc_maps->len)) {
    proc_maps->data = nullptr;
    proc_maps->mmaped_size = 0;
    proc_maps->len = 0;
  }
}

void MemoryMappedSegment::AddAddressRanges(LoadedModule *module) {
  // data_ should be unused on this platform
  CHECK(!data_);
  module->addAddressRange(start, end, IsExecutable(), IsWritable());
}

MemoryMappingLayout::MemoryMappingLayout(bool cache_enabled) {
  // FIXME: in the future we may want to cache the mappings on demand only.
  if (cache_enabled)
    CacheMemoryMappings();

  // Read maps after the cache update to capture the maps/unmaps happening in
  // the process of updating.
  ReadProcMaps(&data_.proc_self_maps);
  if (cache_enabled && data_.proc_self_maps.mmaped_size == 0)
    LoadFromCache();

  Reset();
}

bool MemoryMappingLayout::Error() const {
  return data_.current == nullptr;
}

MemoryMappingLayout::~MemoryMappingLayout() {
  // Only unmap the buffer if it is different from the cached one. Otherwise
  // it will be unmapped when the cache is refreshed.
  if (data_.proc_self_maps.data != cached_proc_self_maps.data)
    UnmapOrDie(data_.proc_self_maps.data, data_.proc_self_maps.mmaped_size);
}

void MemoryMappingLayout::Reset() {
  data_.current = data_.proc_self_maps.data;
}

// static
void MemoryMappingLayout::CacheMemoryMappings() {
  ProcSelfMapsBuff new_proc_self_maps;
  ReadProcMaps(&new_proc_self_maps);
  // Don't invalidate the cache if the mappings are unavailable.
  if (new_proc_self_maps.mmaped_size == 0)
    return;
  std::lock_guard<std::mutex> l(cache_lock);
  if (cached_proc_self_maps.mmaped_size)
    UnmapOrDie(cached_proc_self_maps.data, cached_proc_self_maps.mmaped_size);
  cached_proc_self_maps = new_proc_self_maps;
}

void MemoryMappingLayout::LoadFromCache() {
  std::lock_guard<std::mutex> l(cache_lock);
  if (cached_proc_self_maps.data)
    data_.proc_self_maps = cached_proc_self_maps;
}

void MemoryMappingLayout::DumpListOfModules(
    InternalMmapVectorNoCtor<LoadedModule> *modules) {
  Reset();
  InternalMmapVector<char> module_name(kMaxPathLength);
  MemoryMappedSegment segment(module_name.data(), module_name.size());
  for (uptr i = 0; Next(&segment); i++) {
    const char *cur_name = segment.filename;
    if (cur_name[0] == '\0')
      continue;
    // Don't subtract 'cur_beg' from the first entry:
    // * If a binary is compiled w/o -pie, then the first entry in
    //   process maps is likely the binary itself (all dynamic libs
    //   are mapped higher in address space). For such a binary,
    //   instruction offset in binary coincides with the actual
    //   instruction address in virtual memory (as code section
    //   is mapped to a fixed memory range).
    // * If a binary is compiled with -pie, all the modules are
    //   mapped high at address space (in particular, higher than
    //   shadow memory of the tool), so the module can't be the
    //   first entry.
    uptr base_address = (i ? segment.start : 0) - segment.offset;
    LoadedModule cur_module;
    cur_module.set(cur_name, base_address);
    segment.AddAddressRanges(&cur_module);
    modules->push_back(cur_module);
  }
}

static int TranslateDigit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

// Parse a number and promote 'p' up to the first non-digit character.
static uptr ParseNumber(const char **p, int base) {
  uptr n = 0;
  int d;
  CHECK(base >= 2 && base <= 16);
  while ((d = TranslateDigit(**p)) >= 0 && d < base) {
    n = n * base + d;
    (*p)++;
  }
  return n;
}

static bool IsDecimal(char c) {
  int d = TranslateDigit(c);
  return d >= 0 && d < 10;
}

static uptr ParseHex(const char **p) {
  return ParseNumber(p, 16);
}

static bool IsOneOf(char c, char c1, char c2) {
  return c == c1 || c == c2;
}

bool MemoryMappingLayout::Next(MemoryMappedSegment *segment) {
  if (Error()) return false; // simulate empty maps
  char *last = data_.proc_self_maps.data + data_.proc_self_maps.len;
  if (data_.current >= last) return false;
  const char *next_line =
      (const char *)std::memchr(data_.current, '\n', last - data_.current);
  if (next_line == 0)
    next_line = last;
  // Example: 08048000-08056000 r-xp 00000000 03:0c 64593   /foo/bar
  segment->start = ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, '-');
  segment->end = ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, ' ');
  CHECK(IsOneOf(*data_.current, '-', 'r'));
  segment->protection = 0;
  if (*data_.current++ == 'r') segment->protection |= kProtectionRead;
  CHECK(IsOneOf(*data_.current, '-', 'w'));
  if (*data_.current++ == 'w') segment->protection |= kProtectionWrite;
  CHECK(IsOneOf(*data_.current, '-', 'x'));
  if (*data_.current++ == 'x') segment->protection |= kProtectionExecute;
  CHECK(IsOneOf(*data_.current, 's', 'p'));
  if (*data_.current++ == 's') segment->protection |= kProtectionShared;
  CHECK_EQ(*data_.current++, ' ');
  segment->offset = ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, ' ');
  ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, ':');
  ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, ' ');
  while (IsDecimal(*data_.current)) data_.current++;
  // Qemu may lack the trailing space.
  // https://github.com/google/sanitizers/issues/160
  // CHECK_EQ(*data_.current++, ' ');
  // Skip spaces.
  while (data_.current < next_line && *data_.current == ' ') data_.current++;
  // Fill in the filename.
  if (segment->filename) {
    uptr len =
        Min((uptr)(next_line - data_.current), segment->filename_size - 1);
    std::strncpy(segment->filename, data_.current, len);
    segment->filename[len] = 0;
  }

  data_.current = next_line + 1;
  return true;
}
#endif // SANITIZER_MAC
