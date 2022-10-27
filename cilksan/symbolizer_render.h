// -*- C++ -*-
#ifndef _SYMBOLIZER_RENDER_
#define _SYMBOLIZER_RENDER_

#include <string>

#include "symbolizer.h"

#define FORMAT(f, a)  __attribute__((format(printf, f, a)))

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

void InternalScopedString::append(const char *format, ...) {
  uptr prev_len = length();

  while (true) {
    buffer_.resize(buffer_.capacity());

    va_list args;
    va_start(args, format);
    // uptr sz = VSNPrintf(buffer_.data() + prev_len, buffer_.size() - prev_len,
    //                     format, args);
    uptr sz = vsnprintf(buffer_.data() + prev_len, buffer_.size() - prev_len,
                        format, args);
    va_end(args);
    if (sz < buffer_.size() - prev_len) {
      buffer_.resize(prev_len + sz + 1);
      break;
    }

    buffer_.reserve(buffer_.capacity() * 2);
  }
  CHECK_EQ(buffer_[length()], '\0');
}

const char *StripPathPrefix(const char *filepath,
                            const char *strip_path_prefix) {
  if (!filepath) return nullptr;
  if (!strip_path_prefix) return filepath;
  const char *res = filepath;
  if (const char *pos = std::strstr(filepath, strip_path_prefix))
    res = pos + std::strlen(strip_path_prefix);
  if (res[0] == '.' && res[1] == '/')
    res += 2;
  return res;
}

static const char *DemangleFunctionName(const char *function) {
  if (!function) return nullptr;

//   // NetBSD uses indirection for old threading functions for historical reasons
//   // The mangled names are internal implementation detail and should not be
//   // exposed even in backtraces.
// #if SANITIZER_NETBSD
//   if (!std::strcmp(function, "__libc_mutex_init"))
//     return "pthread_mutex_init";
//   if (!std::strcmp(function, "__libc_mutex_lock"))
//     return "pthread_mutex_lock";
//   if (!std::strcmp(function, "__libc_mutex_trylock"))
//     return "pthread_mutex_trylock";
//   if (!std::strcmp(function, "__libc_mutex_unlock"))
//     return "pthread_mutex_unlock";
//   if (!std::strcmp(function, "__libc_mutex_destroy"))
//     return "pthread_mutex_destroy";
//   if (!std::strcmp(function, "__libc_mutexattr_init"))
//     return "pthread_mutexattr_init";
//   if (!std::strcmp(function, "__libc_mutexattr_settype"))
//     return "pthread_mutexattr_settype";
//   if (!std::strcmp(function, "__libc_mutexattr_destroy"))
//     return "pthread_mutexattr_destroy";
//   if (!std::strcmp(function, "__libc_cond_init"))
//     return "pthread_cond_init";
//   if (!std::strcmp(function, "__libc_cond_signal"))
//     return "pthread_cond_signal";
//   if (!std::strcmp(function, "__libc_cond_broadcast"))
//     return "pthread_cond_broadcast";
//   if (!std::strcmp(function, "__libc_cond_wait"))
//     return "pthread_cond_wait";
//   if (!std::strcmp(function, "__libc_cond_timedwait"))
//     return "pthread_cond_timedwait";
//   if (!std::strcmp(function, "__libc_cond_destroy"))
//     return "pthread_cond_destroy";
//   if (!std::strcmp(function, "__libc_rwlock_init"))
//     return "pthread_rwlock_init";
//   if (!std::strcmp(function, "__libc_rwlock_rdlock"))
//     return "pthread_rwlock_rdlock";
//   if (!std::strcmp(function, "__libc_rwlock_wrlock"))
//     return "pthread_rwlock_wrlock";
//   if (!std::strcmp(function, "__libc_rwlock_tryrdlock"))
//     return "pthread_rwlock_tryrdlock";
//   if (!std::strcmp(function, "__libc_rwlock_trywrlock"))
//     return "pthread_rwlock_trywrlock";
//   if (!std::strcmp(function, "__libc_rwlock_unlock"))
//     return "pthread_rwlock_unlock";
//   if (!std::strcmp(function, "__libc_rwlock_destroy"))
//     return "pthread_rwlock_destroy";
//   if (!std::strcmp(function, "__libc_thr_keycreate"))
//     return "pthread_key_create";
//   if (!std::strcmp(function, "__libc_thr_setspecific"))
//     return "pthread_setspecific";
//   if (!std::strcmp(function, "__libc_thr_getspecific"))
//     return "pthread_getspecific";
//   if (!std::strcmp(function, "__libc_thr_keydelete"))
//     return "pthread_key_delete";
//   if (!std::strcmp(function, "__libc_thr_once"))
//     return "pthread_once";
//   if (!std::strcmp(function, "__libc_thr_self"))
//     return "pthread_self";
//   if (!std::strcmp(function, "__libc_thr_exit"))
//     return "pthread_exit";
//   if (!std::strcmp(function, "__libc_thr_setcancelstate"))
//     return "pthread_setcancelstate";
//   if (!std::strcmp(function, "__libc_thr_equal"))
//     return "pthread_equal";
//   if (!std::strcmp(function, "__libc_thr_curcpu"))
//     return "pthread_curcpu_np";
//   if (!std::strcmp(function, "__libc_thr_sigsetmask"))
//     return "pthread_sigmask";
// #endif

  return function;
}

static const char *StripFunctionName(const char *function, const char *prefix) {
  if (!function) return nullptr;
  if (!prefix) return function;
  uptr prefix_len = std::strlen(prefix);
  if (0 == std::strncmp(function, prefix, prefix_len))
    return function + prefix_len;
  return function;
}

static void MaybeBuildIdToBuffer(const AddressInfo &info, bool PrefixSpace,
                                 InternalScopedString *buffer) {
  if (info.uuid_size) {
    if (PrefixSpace)
      buffer->append(" ");
    buffer->append("(BuildId: ");
    for (uptr i = 0; i < info.uuid_size; ++i) {
      buffer->append("%02x", info.uuid[i]);
    }
    buffer->append(")");
  }
}

void RenderSourceLocation(InternalScopedString *buffer, const char *file,
                          int line, int column, bool vs_style,
                          const char *strip_path_prefix) {
  if (vs_style && line > 0) {
    buffer->append("%s(%d", StripPathPrefix(file, strip_path_prefix), line);
    if (column > 0)
      buffer->append(",%d", column);
    buffer->append(")");
    return;
  }

  buffer->append("%s", StripPathPrefix(file, strip_path_prefix));
  if (line > 0) {
    buffer->append(":%d", line);
    if (column > 0)
      buffer->append(":%d", column);
  }
}

void RenderModuleLocation(InternalScopedString *buffer, const char *module,
                          uptr offset, ModuleArch arch,
                          const char *strip_path_prefix) {
  buffer->append("(%s", StripPathPrefix(module, strip_path_prefix));
  if (arch != kModuleArchUnknown) {
    buffer->append(":%s", ModuleArchToString(arch));
  }
  buffer->append("+0x%zx)", offset);
}

// Denotes fake PC values that come from JIT/JAVA/etc.
// For such PC values __tsan_symbolize_external_ex() will be called.
const u64 kExternalPCBit = 1ULL << 60;

static const char kDefaultFormat[] = "    #%n %p %F %L";

// Render the contents of "info" structure, which represents the contents of
// stack frame "frame_no" and appends it to the "buffer". "format" is a
// string with placeholders, which is copied to the output with
// placeholders substituted with the contents of "info". For example,
// format string
//   "  frame %n: function %F at %S"
// will be turned into
//   "  frame 10: function foo::bar() at my/file.cc:10"
// You may additionally pass "strip_path_prefix" to strip prefixes of paths to
// source files and modules, and "strip_func_prefix" to strip prefixes of
// function names.
// Here's the full list of available placeholders:
//   %% - represents a '%' character;
//   %n - frame number (copy of frame_no);
//   %p - PC in hex format;
//   %m - path to module (binary or shared object);
//   %o - offset in the module in hex format;
//   %f - function name;
//   %q - offset in the function in hex format (*if available*);
//   %s - path to source file;
//   %l - line in the source file;
//   %c - column in the source file;
//   %F - if function is known to be <foo>, prints "in <foo>", possibly
//        followed by the offset in this function, but only if source file
//        is unknown;
//   %S - prints file/line/column information;
//   %L - prints location information: file/line/column, if it is known, or
//        module+offset if it is known, or (<unknown module>) string.
//   %M - prints module basename and offset, if it is known, or PC.
void RenderFrame(InternalScopedString *buffer, const char *format, int frame_no,
                 uptr address, const AddressInfo *info, bool vs_style = false,
                 const char *strip_path_prefix = "",
		 const char *strip_func_prefix = "") {
  // info will be null in the case where symbolization is not needed for the
  // given format. This ensures that the code below will get a hard failure
  // rather than print incorrect information in case RenderNeedsSymbolization
  // ever ends up out of sync with this function. If non-null, the addresses
  // should match.
  CHECK(!info || address == info->address);
  if (0 == std::strcmp(format, "DEFAULT"))
    format = kDefaultFormat;
  for (const char *p = format; *p != '\0'; p++) {
    if (*p != '%') {
      buffer->append("%c", *p);
      continue;
    }
    p++;
    switch (*p) {
    case '%':
      buffer->append("%%");
      break;
    // Frame number and all fields of AddressInfo structure.
    case 'n':
      buffer->append("%u", frame_no);
      break;
    case 'p':
      buffer->append("0x%zx", address);
      break;
    case 'm':
      buffer->append("%s", StripPathPrefix(info->module, strip_path_prefix));
      break;
    case 'o':
      buffer->append("0x%zx", info->module_offset);
      break;
    case 'b':
      MaybeBuildIdToBuffer(*info, /*PrefixSpace=*/false, buffer);
      break;
    case 'f':
      buffer->append("%s", DemangleFunctionName(StripFunctionName(
                               info->function, strip_func_prefix)));
      break;
    case 'q':
      buffer->append("0x%zx", info->function_offset != AddressInfo::kUnknown
                                  ? info->function_offset
                                  : 0x0);
      break;
    case 's':
      buffer->append("%s", StripPathPrefix(info->file, strip_path_prefix));
      break;
    case 'l':
      buffer->append("%d", info->line);
      break;
    case 'c':
      buffer->append("%d", info->column);
      break;
    // Smarter special cases.
    case 'F':
      // Function name and offset, if file is unknown.
      if (info->function) {
        buffer->append("in %s", DemangleFunctionName(StripFunctionName(
                                    info->function, strip_func_prefix)));
        if (!info->file && info->function_offset != AddressInfo::kUnknown)
          buffer->append("+0x%zx", info->function_offset);
      }
      break;
    case 'S':
      // File/line information.
      RenderSourceLocation(buffer, info->file, info->line, info->column,
                           vs_style, strip_path_prefix);
      break;
    case 'L':
      // Source location, or module location.
      if (info->file) {
        RenderSourceLocation(buffer, info->file, info->line, info->column,
                             vs_style, strip_path_prefix);
      } else if (info->module) {
        RenderModuleLocation(buffer, info->module, info->module_offset,
                             info->module_arch, strip_path_prefix);

        MaybeBuildIdToBuffer(*info, /*PrefixSpace=*/true, buffer);
      } else {
        buffer->append("(<unknown module>)");
      }
      break;
    case 'M':
      // Module basename and offset, or PC.
      if (address & kExternalPCBit) {
        // There PCs are not meaningful.
      } else if (info->module) {
        // Always strip the module name for %M.
        RenderModuleLocation(buffer, StripModuleName(info->module),
                             info->module_offset, info->module_arch, "");
        MaybeBuildIdToBuffer(*info, /*PrefixSpace=*/true, buffer);
      } else {
        buffer->append("(%p)", (void *)address);
      }
      break;
    default:
      // Report("Unsupported specifier in stack frame format: %c (%p)!\n", *p,
      //        (void *)p);
      // Die();
      cilksan_assert(false && "Unsupported specifier in stack frame format.");
    }
  }
}

bool RenderNeedsSymbolization(const char *format) {
  if (0 == std::strcmp(format, "DEFAULT"))
    format = kDefaultFormat;
  for (const char *p = format; *p != '\0'; p++) {
    if (*p != '%')
      continue;
    p++;
    switch (*p) {
      case '%':
        break;
      case 'n':
        // frame_no
        break;
      case 'p':
        // address
        break;
      default:
        return true;
    }
  }
  return false;
}

class StackTraceTextPrinter {
 public:
  StackTraceTextPrinter(const char *stack_trace_fmt, char frame_delimiter,
                        InternalScopedString *output,
                        InternalScopedString *dedup_token)
      : stack_trace_fmt_(stack_trace_fmt),
        frame_delimiter_(frame_delimiter),
        output_(output),
        dedup_token_(dedup_token),
        symbolize_(RenderNeedsSymbolization(stack_trace_fmt)) {}

  bool ProcessAddressFrames(uptr pc) {
    SymbolizedStack *frames = symbolize_
                                  ? Symbolizer::GetOrInit()->SymbolizePC(pc)
                                  : SymbolizedStack::New(pc);
    if (!frames)
      return false;

    for (SymbolizedStack *cur = frames; cur; cur = cur->next) {
      uptr prev_len = output_->length();
      RenderFrame(output_, stack_trace_fmt_, frame_num_++, cur->info.address,
                  symbolize_ ? &cur->info : nullptr, false, "");
                  // common_flags()->symbolize_vs_style,
                  // common_flags()->strip_path_prefix);

      if (prev_len != output_->length())
        output_->append("%c", frame_delimiter_);

      ExtendDedupToken(cur);
    }
    frames->ClearAll();
    return true;
  }

 private:
  // Extend the dedup token by appending a new frame.
  void ExtendDedupToken(SymbolizedStack *stack) {
    if (!dedup_token_)
      return;

    if (dedup_frames_-- > 0) {
      if (dedup_token_->length())
        dedup_token_->append("--");
      if (stack->info.function != nullptr)
        dedup_token_->append("%s", stack->info.function);
    }
  }

  const char *stack_trace_fmt_;
  const char frame_delimiter_;
  // int dedup_frames_ = common_flags()->dedup_token_length;
  int dedup_frames_ = 0;
  uptr frame_num_ = 0;
  InternalScopedString *output_;
  InternalScopedString *dedup_token_;
  const bool symbolize_ = false;
};

// struct StackTrace {
//   const uptr *trace;
//   u32 size;
//   u32 tag;

//   static const int TAG_UNKNOWN = 0;
//   static const int TAG_ALLOC = 1;
//   static const int TAG_DEALLOC = 2;
//   static const int TAG_CUSTOM = 100; // Tool specific tags start here.

//   StackTrace() : trace(nullptr), size(0), tag(0) {}
//   StackTrace(const uptr *trace, u32 size) : trace(trace), size(size), tag(0) {}
//   StackTrace(const uptr *trace, u32 size, u32 tag)
//       : trace(trace), size(size), tag(tag) {}

//   // Prints a symbolized stacktrace, followed by an empty line.
//   void Print() const;

//   // Prints a symbolized stacktrace to the output string, followed by an empty
//   // line.
//   void PrintTo(InternalScopedString *output) const;

//   // Prints a symbolized stacktrace to the output buffer, followed by an empty
//   // line. Returns the number of symbols that should have been written to buffer
//   // (not including trailing '\0'). Thus, the string is truncated iff return
//   // value is not less than "out_buf_size".
//   uptr PrintTo(char *out_buf, uptr out_buf_size) const;

//   // static bool WillUseFastUnwind(bool request_fast_unwind) {
//   //   if (!SANITIZER_CAN_FAST_UNWIND)
//   //     return false;
//   //   if (!SANITIZER_CAN_SLOW_UNWIND)
//   //     return true;
//   //   return request_fast_unwind;
//   // }

//   static uptr GetCurrentPc();
//   static inline uptr GetPreviousInstructionPc(uptr pc);
//   static uptr GetNextInstructionPc(uptr pc);
// };

// void StackTrace::PrintTo(InternalScopedString *output) const {
//   CHECK(output);

//   InternalScopedString dedup_token;
//   // StackTraceTextPrinter printer(common_flags()->stack_trace_format, '\n',
//   //                               output, &dedup_token);
//   StackTraceTextPrinter printer("DEFAULT", '\n', output, &dedup_token);

//   if (trace == nullptr || size == 0) {
//     output->append("    <empty stack>\n\n");
//     return;
//   }

//   for (uptr i = 0; i < size && trace[i]; i++) {
//     // PCs in stack traces are actually the return addresses, that is,
//     // addresses of the next instructions after the call.
//     uptr pc = GetPreviousInstructionPc(trace[i]);
//     CHECK(printer.ProcessAddressFrames(pc));
//   }

//   // Always add a trailing empty line after stack trace.
//   output->append("\n");

//   // Append deduplication token, if non-empty.
//   if (dedup_token.length())
//     output->append("DEDUP_TOKEN: %s\n", dedup_token.data());
// }

// static void CopyStringToBuffer(const InternalScopedString &str, char *out_buf,
//                                uptr out_buf_size) {
//   if (!out_buf_size)
//     return;

//   CHECK_GT(out_buf_size, 0);
//   uptr copy_size = Min(str.length(), out_buf_size - 1);
//   std::memcpy(out_buf, str.data(), copy_size);
//   out_buf[copy_size] = '\0';
// }

// uptr StackTrace::PrintTo(char *out_buf, uptr out_buf_size) const {
//   CHECK(out_buf);

//   InternalScopedString output;
//   PrintTo(&output);
//   CopyStringToBuffer(output, out_buf, out_buf_size);

//   return output.length();
// }

// void StackTrace::Print() const {
//   InternalScopedString output;
//   PrintTo(&output);
//   printf("%s", output.data());
// }

#endif // _SYMBOLIZER_RENDER_
