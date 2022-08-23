#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

// Ensure that __cilkscale__ is defined, so we can provide a nontrivial
// definition of getworkspan().
#ifndef __cilkscale__
#define __cilkscale__
#endif

#include "shadow_stack.h"
#include <csi/csi.h>
#include <iostream>
#include <fstream>

#define CILKTOOL_API extern "C" __attribute__((visibility("default")))

#ifndef SERIAL_TOOL
#define SERIAL_TOOL 1
#endif

#ifndef TRACE_CALLS
#define TRACE_CALLS 0
#endif

#ifndef ENABLE_CSI_SF
#define ENABLE_CSI_SF 1
#endif

#if SERIAL_TOOL
FILE *err_io = stderr;
#else
#include <cilk/cilk_api.h>
#include <cilk/ostream_reducer.h>

using out_reducer = cilk::ostream_reducer<char>;
#endif

// defined in libopencilk
extern "C" int __cilkrts_is_initialized(void);
extern "C" void __cilkrts_internal_set_nworkers(unsigned int nworkers);

///////////////////////////////////////////////////////////////////////////
// Data structures for tracking work and span.

bool CILKSCALE_INITIALIZED = false;
bool USING_CSI_SF = false;

// Top-level class to manage the state of the global Cilkscale tool.  This class
// interface allows the tool to initialize data structures, such as a
// std::ostream and a std::ofstream, only after the standard libraries they rely
// on have been initialized, and to destroy those structures before those
// libraries are deinitialized.
class CilkscaleImpl_t {
public:
  // Shadow-stack data structure, for managing work-span variables.
#if SERIAL_TOOL
  shadow_stack_t *shadow_stack = nullptr;
#else
  shadow_stack_reducer *shadow_stack = nullptr;
#endif

#if SERIAL_TOOL
  shadow_stack_top_bot_t ss;
#else
  shadow_stack_top_bot_reducer ss;
#endif

  // Output stream for printing results.
  std::ostream &outs = std::cout;
  std::ofstream outf;
#if !SERIAL_TOOL
  out_reducer *outf_red = nullptr;
#endif

  std::basic_ostream<char> *out_view() {
#if !SERIAL_TOOL
    // TODO: The compiler does not correctly bind the hyperobject
    // type to a reference, otherwise a reference return value would
    // be more conventional C++.
    if (outf_red)
      return &*outf_red;
#endif
    if (outf.is_open())
      return &outf;
    return &outs;
  }

  CilkscaleImpl_t();
  ~CilkscaleImpl_t();
};

// Top-level Cilkscale tool.
static CilkscaleImpl_t *create_tool(void) {
  if (!__cilkrts_is_initialized())
    // If the OpenCilk runtime is not yet initialized, then csi_init will
    // register a call to init_tool to initialize the tool after the runtime is
    // initialized.
    return nullptr;

  // Otherwise, ordered dynamic initalization should ensure that it's safe to
  // create the tool.
  return new CilkscaleImpl_t();
}
CilkscaleImpl_t *tool = create_tool();

///////////////////////////////////////////////////////////////////////////
// Utilities for printing analysis results

// Ensure that a proper header has been emitted to OS.
template<class Out>
static void ensure_header(Out &OS) {
  static bool PRINT_STARTED = false;
  if (PRINT_STARTED)
    return;

  OS << "tag,work (" << cilk_time_t::units << ")"
     << ",span (" << cilk_time_t::units << ")"
     << ",parallelism"
     << ",burdened_span (" << cilk_time_t::units << ")"
     << ",burdened_parallelism\n";

  PRINT_STARTED = true;
}

// Emit the given results to OS.
template<class Out>
static void print_results(Out &OS, const char *tag, cilk_time_t work,
                          cilk_time_t span, cilk_time_t bspan) {
  OS << tag
     << "," << work << "," << span << "," << work.get_val_d() / span.get_val_d()
     << "," << bspan << "," << work.get_val_d() / bspan.get_val_d() << "\n";
}

// Emit the results from the overall program execution to the proper output
// stream.
static void print_analysis(void) {
  assert(CILKSCALE_INITIALIZED);
  std::basic_ostream<char> &output = *tool->out_view();
  if (USING_CSI_SF && tool->ss.get_bot().contin_work > cilk_time_t::zero()) {
    shadow_stack_frame_t &bot = tool->ss.get_bot();
    assert(frame_type::NONE != bot.type);

    cilk_time_t work = bot.contin_work;
    cilk_time_t span = bot.contin_span;
    cilk_time_t bspan = bot.contin_bspan;

    ensure_header(output);
    print_results(output, "", work, span, bspan);
    return;
  }
  shadow_stack_frame_t &bottom = tool->shadow_stack->peek_bot();

  assert(frame_type::NONE != bottom.type);

  cilk_time_t work = bottom.contin_work;
  cilk_time_t span = bottom.contin_span;
  cilk_time_t bspan = bottom.contin_bspan;

  ensure_header(output);
  print_results(output, "", work, span, bspan);
}

///////////////////////////////////////////////////////////////////////////
// Tool startup and shutdown

#if SERIAL_TOOL
// Ensure that this tool is run serially
static inline void ensure_serial_tool(void) {
  fprintf(stderr, "Forcing CILK_NWORKERS=1.\n");
  if (__cilkrts_is_initialized()) {
    __cilkrts_internal_set_nworkers(1);
  } else {
    // Force the number of Cilk workers to be 1.
    char *e = getenv("CILK_NWORKERS");
    if (!e || 0 != strcmp(e, "1")) {
      if (setenv("CILK_NWORKERS", "1", 1)) {
        fprintf(stderr, "Error setting CILK_NWORKERS to be 1\n");
        exit(1);
      }
    }
  }
}
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

CilkscaleImpl_t::CilkscaleImpl_t() {
#if SERIAL_TOOL
  shadow_stack = new shadow_stack_t(frame_type::MAIN);
#else
  shadow_stack = new shadow_stack_reducer();
  __cilkrts_reducer_register(shadow_stack, sizeof(*shadow_stack),
                             &shadow_stack_t::identity,
                             &shadow_stack_t::reduce);

  __cilkrts_reducer_register(__builtin_addressof(ss), sizeof(ss),
                             &shadow_stack_top_bot_t::identity,
                             &shadow_stack_top_bot_t::reduce);
#endif

  const char *envstr = getenv("CILKSCALE_OUT");
  if (envstr)
    outf.open(envstr);

#if !SERIAL_TOOL
  outf_red = new out_reducer((outf.is_open() ? outf : outs));
  __cilkrts_reducer_register(
      outf_red, sizeof(*outf_red),
      &cilk::ostream_view<char, std::char_traits<char>>::identity,
      &cilk::ostream_view<char, std::char_traits<char>>::reduce);
#endif

  // Initialize ss.
  // FIXME: Ideally, the initial view of ss would be default-constructed, but
  // it's not yet because structure-member reducers are not yet supported.
  ss.get_top().init(frame_type::SPAWNER);
  ss.set_bot(ss.get_top());
  ss.start.gettime();

  shadow_stack->push(frame_type::SPAWNER);
  shadow_stack->start.gettime();
}

CilkscaleImpl_t::~CilkscaleImpl_t() {
  if (USING_CSI_SF) {
    tool->ss.stop.gettime();
    duration_t strand_time = tool->ss->elapsed_time();

    shadow_stack_frame_t &top = tool->ss.get_top();
    top.contin_work += strand_time;
    top.contin_span += strand_time;
    top.contin_bspan += strand_time;
  } else {
    tool->shadow_stack->stop.gettime();
    duration_t strand_time = tool->shadow_stack->elapsed_time();
    shadow_stack_frame_t &bottom = tool->shadow_stack->peek_bot();

    bottom.contin_work += strand_time;
    bottom.contin_span += strand_time;
    bottom.contin_bspan += strand_time;
  }

  print_analysis();

  if (outf.is_open())
    outf.close();
#if !SERIAL_TOOL
  __cilkrts_reducer_unregister(shadow_stack);
  __cilkrts_reducer_unregister(&ss);
#endif
  delete shadow_stack;
  shadow_stack = nullptr;

#if !SERIAL_TOOL
  __cilkrts_reducer_unregister(outf_red);
  delete outf_red;
  outf_red = nullptr;
#endif
}

#pragma clang diagnostic pop

///////////////////////////////////////////////////////////////////////////
// Hooks for operating the tool.

// Custom function to intialize tool after the OpenCilk runtime is initialized.
static void init_tool(void) {
  assert(nullptr == tool && "Tool already initialized");
  tool = new CilkscaleImpl_t();
}

static void destroy_tool(void) {
  if (tool) {
    delete tool;
    tool = nullptr;
  }

  CILKSCALE_INITIALIZED = false;
}

CILKTOOL_API void __csi_init() {
#if TRACE_CALLS
  fprintf(stderr, "__csi_init()\n");
#endif

#if SERIAL_TOOL
  ensure_serial_tool();
  atexit(destroy_tool);
#else
  if (!__cilkrts_is_initialized())
    __cilkrts_atinit(init_tool);

  __cilkrts_atexit(destroy_tool);
#endif

  CILKSCALE_INITIALIZED = true;
}

CILKTOOL_API void __csi_unit_init(const char *const file_name,
                                  const instrumentation_counts_t counts) {
  return;
}

struct __csi_stack_frame_t {
  shadow_stack_frame_t frame;
  shadow_stack_frame_t *parent;
};

CILKTOOL_API
void __csi_bb_entry(__csi_stack_frame_t *sf, const csi_id_t bb_id,
                    const bb_prop_t prop) {
  if (__builtin_expect(!CILKSCALE_INITIALIZED, false))
    return;

  if (ENABLE_CSI_SF && sf) {
    shadow_stack_frame_t &bot = tool->ss.get_bot();
    get_bb_time(&bot.contin_work, &bot.contin_span, &bot.contin_bspan, bb_id);
    return;
  }
  shadow_stack_frame_t &bottom = tool->shadow_stack->peek_bot();
  get_bb_time(&bottom.contin_work, &bottom.contin_span, &bottom.contin_bspan,
              bb_id);
  return;
}

CILKTOOL_API
void __csi_bb_exit(__csi_stack_frame_t *sf, const csi_id_t bb_id,
                   const bb_prop_t prop) {
  return;
}

CILKTOOL_API
void __csi_func_entry(__csi_stack_frame_t *sf, const csi_id_t func_id,
                      const func_prop_t prop) {
  if (__builtin_expect(!CILKSCALE_INITIALIZED, false))
    return;
  if (__builtin_expect(!tool, false))
    init_tool();
  if (!USING_CSI_SF && ENABLE_CSI_SF && sf) {
    USING_CSI_SF = true;
    fprintf(stderr, "Using CSI stack frame\n");
  }
  if (!prop.may_spawn)
    return;

  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;
    ss.stop.gettime();

#if TRACE_CALLS
    fprintf(stderr, "[W%d] func_entry(%ld)\n", __cilkrts_get_worker_number(),
            func_id);
#endif

    duration_t strand_time = ss.elapsed_time();
    shadow_stack_frame_t &bot = ss.get_bot();
    bot.contin_work += strand_time;
    bot.contin_span += strand_time;
    bot.contin_bspan += strand_time;

    sf->frame.init(frame_type::SPAWNER, bot.contin_work, bot.contin_span,
                   bot.contin_bspan);

    sf->parent = &ss.get_bot();
    ss.set_bot(sf->frame);

    // ss.start.gettime();
    // Because of the high overhead of calling gettime(), especially compared to
    // the running time of the operations in this hook, the work and span
    // measurements appear more stable if we simply use the recorded time as the
    // new start time.
    ss.start = ss.stop;
    return;
  }
  
  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

#if TRACE_CALLS
  fprintf(stderr, "[W%d] func_entry(%ld)\n", __cilkrts_get_worker_number(),
          func_id);
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;

  shadow_stack_frame_t &p_bottom = stack.peek_bot();
  cilk_time_t p_contin_work = p_bottom.contin_work;
  cilk_time_t p_contin_span = p_bottom.contin_span;
  cilk_time_t p_contin_bspan = p_bottom.contin_bspan;

  // Push new frame onto the stack
  stack.push(frame_type::SPAWNER, p_contin_work, p_contin_span, p_contin_bspan);

  // stack.start.gettime();
  // Because of the high overhead of calling gettime(), especially compared to
  // the running time of the operations in this hook, the work and span
  // measurements appear more stable if we simply use the recorded time as the
  // new start time.
  stack.start = stack.stop;
}

CILKTOOL_API
void __csi_func_exit(__csi_stack_frame_t *sf, const csi_id_t func_exit_id,
                     const csi_id_t func_id, const func_exit_prop_t prop) {
  if (__builtin_expect(!CILKSCALE_INITIALIZED, false))
    return;
  if (!prop.may_spawn)
    return;

  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;
    ss.stop.gettime();

#if TRACE_CALLS
    fprintf(stderr, "[W%d] func_exit(%ld)\n", __cilkrts_get_worker_number(),
            func_id);
#endif
    duration_t strand_time = ss.elapsed_time();
    assert(cilk_time_t::zero() == sf->frame.lchild_span);
    shadow_stack_frame_t &bot = sf->frame;
    // assert(cilk_time_t::zero() == sf->frame->lchild_span);
    // shadow_stack_frame_t &bot = *sf->frame;
    shadow_stack_frame_t &p_bot = *sf->parent;

    p_bot.contin_work = bot.contin_work + strand_time;
    p_bot.contin_span = bot.contin_span + strand_time;
    p_bot.contin_bspan = bot.contin_bspan + strand_time;

    ss.set_bot(*sf->parent);

    // ss.start.gettime();
    // Because of the high overhead of calling gettime(), especially compared to
    // the running time of the operations in this hook, the work and span
    // measurements appear more stable if we simply use the recorded time as the
    // new start time.
    ss.start = ss.stop;

    // std::basic_ostream<char> &output = *tool->out_view();
    // print_results(output, "", p_bot.contin_work, p_bot.contin_span, p_bot.contin_bspan);
    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

#if TRACE_CALLS
  fprintf(stderr, "[W%d] func_exit(%ld)\n", __cilkrts_get_worker_number(),
          func_id);
#endif

  duration_t strand_time = stack.elapsed_time();

  assert(cilk_time_t::zero() == stack.peek_bot().lchild_span);

  // Pop the stack
  shadow_stack_frame_t &c_bottom = stack.pop();
  shadow_stack_frame_t &p_bottom = stack.peek_bot();

  p_bottom.contin_work = c_bottom.contin_work + strand_time;
  p_bottom.contin_span = c_bottom.contin_span + strand_time;
  p_bottom.contin_bspan = c_bottom.contin_bspan + strand_time;

  // stack.start.gettime();
  // Because of the high overhead of calling gettime(), especially compared to
  // the running time of the operations in this hook, the work and span
  // measurements appear more stable if we simply use the recorded time as the
  // new start time.
  stack.start = stack.stop;
}

CILKTOOL_API
void __csi_detach(__csi_stack_frame_t *sf, const csi_id_t detach_id,
                  const int32_t *has_spawned) {
  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;
    ss.stop.gettime();


#if TRACE_CALLS
    fprintf(stderr, "[W%d] detach(%ld)\n", __cilkrts_get_worker_number(),
            detach_id);
#endif

    duration_t strand_time = ss.elapsed_time();
    shadow_stack_frame_t &bot = sf->frame;
    bot.contin_work += strand_time;
    bot.contin_span += strand_time;
    bot.contin_bspan += strand_time;

    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

#if TRACE_CALLS
  fprintf(stderr, "[W%d] detach(%ld)\n", __cilkrts_get_worker_number(),
          detach_id);
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;
}

CILKTOOL_API
void __csi_task(__csi_stack_frame_t *sf, const csi_id_t task_id,
                const csi_id_t detach_id, const task_prop_t prop) {
  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

#if TRACE_CALLS
    fprintf(stderr, "[W%d] task(%ld, %ld)\n", __cilkrts_get_worker_number(),
            task_id, detach_id);
#endif
    shadow_stack_frame_t &p_bot = ss.get_bot();
    shadow_stack_frame_t &bot = sf->frame;
    bot.init(frame_type::HELPER, p_bot.contin_work, p_bot.contin_span,
             p_bot.contin_bspan);

    sf->parent = &ss.get_bot();
    ss.set_bot(sf->frame);

    ss.start.gettime();
    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

#if TRACE_CALLS
  fprintf(stderr, "[W%d] task(%ld, %ld)\n", __cilkrts_get_worker_number(),
          task_id, detach_id);
#endif

  shadow_stack_frame_t &p_bottom = stack.peek_bot();
  cilk_time_t p_contin_work = p_bottom.contin_work;
  cilk_time_t p_contin_span = p_bottom.contin_span;
  cilk_time_t p_contin_bspan = p_bottom.contin_bspan;

  // Push new frame onto the stack.
  stack.push(frame_type::HELPER, p_contin_work, p_contin_span, p_contin_bspan);

  stack.start.gettime();
}

CILKTOOL_API
void __csi_task_exit(__csi_stack_frame_t *sf, const csi_id_t task_exit_id,
                     const csi_id_t task_id, const csi_id_t detach_id,
                     const task_exit_prop_t prop) {
  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

    ss.stop.gettime();

#if TRACE_CALLS
    fprintf(stderr, "[W%d] task_exit(%ld, %ld, %ld)\n",
            __cilkrts_get_worker_number(), task_exit_id, task_id, detach_id);
#endif

    duration_t strand_time = ss.elapsed_time();
    shadow_stack_frame_t &bot = sf->frame;
    // shadow_stack_frame_t &bot = *sf->frame;
    bot.contin_work += strand_time;
    bot.contin_span += strand_time;
    bot.contin_bspan += strand_time;

    assert(cilk_time_t::zero() == bot.lchild_span);

    shadow_stack_frame_t &p_bot = *sf->parent;
    p_bot.achild_work += bot.contin_work - p_bot.contin_work;
    if (bot.contin_span > p_bot.lchild_span)
      p_bot.lchild_span = bot.contin_span;
    if (bot.contin_bspan + cilkscale_timer_t::burden > p_bot.lchild_bspan)
      p_bot.lchild_bspan = bot.contin_bspan + cilkscale_timer_t::burden;

    ss.set_bot(*sf->parent);
    // delete sf->frame;
    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

#if TRACE_CALLS
  fprintf(stderr, "[W%d] task_exit(%ld, %ld, %ld)\n",
          __cilkrts_get_worker_number(), task_exit_id, task_id, detach_id);
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;

  assert(cilk_time_t::zero() == bottom.lchild_span);

  // Pop the stack
  shadow_stack_frame_t &c_bottom = stack.pop();
  shadow_stack_frame_t &p_bottom = stack.peek_bot();
  p_bottom.achild_work += c_bottom.contin_work - p_bottom.contin_work;
  // Check if the span of c_bottom exceeds that of the previous longest child.
  if (c_bottom.contin_span > p_bottom.lchild_span)
    p_bottom.lchild_span = c_bottom.contin_span;
  if (c_bottom.contin_bspan + cilkscale_timer_t::burden
      > p_bottom.lchild_bspan)
    p_bottom.lchild_bspan = c_bottom.contin_bspan + cilkscale_timer_t::burden;
}

CILKTOOL_API
void __csi_detach_continue(__csi_stack_frame_t *sf,
                           const csi_id_t detach_continue_id,
                           const csi_id_t detach_id,
                           const detach_continue_prop_t prop) {
  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

#if TRACE_CALLS
    fprintf(stderr, "[W%d] detach_continue(%ld, %ld, %ld)\n",
            __cilkrts_get_worker_number(), detach_continue_id, detach_id, prop);
#endif
    // We use ss.get_bot() here, instead of sf->frame, in case this continuation
    // was stolen.
    shadow_stack_frame_t &bot = ss.get_bot();
    if (prop.is_unwind) {
      // In opencilk, upon reaching the unwind destination of a detach, all
      // spawned child computations have been synced.  Hence we replicate the
      // logic from after_sync here to compute work and span.

      // Add achild_work to contin_work, and reset contin_work.
      bot.contin_work += bot.achild_work;
      bot.achild_work = cilk_time_t::zero();

      // Select the largest of lchild_span and contin_span, and then reset
      // lchild_span.
      if (bot.lchild_span > bot.contin_span)
        bot.contin_span = bot.lchild_span;
      bot.lchild_span = cilk_time_t::zero();

      if (bot.lchild_bspan > bot.contin_bspan)
        bot.contin_bspan = bot.lchild_bspan;
      bot.lchild_bspan = cilk_time_t::zero();
    } else {
      bot.contin_bspan += cilkscale_timer_t::burden;
    }
    ss.start.gettime();
    return;
  }

  // In the continuation
  shadow_stack_t &stack = *&*tool->shadow_stack;

#if TRACE_CALLS
  fprintf(stderr, "[W%d] detach_continue(%ld, %ld, %ld)\n",
          __cilkrts_get_worker_number(), detach_continue_id, detach_id, prop);
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();

  if (prop.is_unwind) {
    // In opencilk, upon reaching the unwind destination of a detach, all
    // spawned child computations have been synced.  Hence we replicate the
    // logic from after_sync here to compute work and span.

    // Add achild_work to contin_work, and reset contin_work.
    bottom.contin_work += bottom.achild_work;
    bottom.achild_work = cilk_time_t::zero();

    // Select the largest of lchild_span and contin_span, and then reset
    // lchild_span.
    if (bottom.lchild_span > bottom.contin_span)
      bottom.contin_span = bottom.lchild_span;
    bottom.lchild_span = cilk_time_t::zero();

    if (bottom.lchild_bspan > bottom.contin_bspan)
      bottom.contin_bspan = bottom.lchild_bspan;
    bottom.lchild_bspan = cilk_time_t::zero();
  } else {
    bottom.contin_bspan += cilkscale_timer_t::burden;
  }

  stack.start.gettime();
}

CILKTOOL_API
void __csi_before_sync(__csi_stack_frame_t *sf, const csi_id_t sync_id,
                       const int32_t *has_spawned) {
  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

    ss.stop.gettime();

#if TRACE_CALLS
    fprintf(stderr, "[W%d] before_sync(%ld)\n", __cilkrts_get_worker_number(),
            sync_id);
#endif

    duration_t strand_time = ss.elapsed_time();
    shadow_stack_frame_t &bot = ss.get_bot();
    bot.contin_work += strand_time;
    bot.contin_span += strand_time;
    bot.contin_bspan += strand_time;
    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

#if TRACE_CALLS
  fprintf(stderr, "[W%d] before_sync(%ld)\n", __cilkrts_get_worker_number(),
          sync_id);
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;
}

CILKTOOL_API
void __csi_after_sync(__csi_stack_frame_t *sf, const csi_id_t sync_id,
                      const int32_t *has_spawned) {
  if (ENABLE_CSI_SF && sf) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

#if TRACE_CALLS
    fprintf(stderr, "[W%d] after_sync(%ld)\n", __cilkrts_get_worker_number(),
            sync_id);
#endif

    // Update the work and span recorded for the bottom-most frame on the stack.
    // shadow_stack_frame_t &bot = *tool->ss.bot;
    shadow_stack_frame_t &bot = ss.get_bot();
    // Add achild_work to contin_work, and reset achild_work.
    bot.contin_work += bot.achild_work;
    bot.achild_work = cilk_time_t::zero();

    // Select the largest of lchild_span and contin_span, and then reset
    // lchild_span.
    if (bot.lchild_span > bot.contin_span)
      bot.contin_span = bot.lchild_span;
    bot.lchild_span = cilk_time_t::zero();

    if (bot.lchild_bspan > bot.contin_bspan)
      bot.contin_bspan = bot.lchild_bspan;
    bot.lchild_bspan = cilk_time_t::zero();

    ss.start.gettime();
    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

#if TRACE_CALLS
  fprintf(stderr, "[W%d] after_sync(%ld)\n", __cilkrts_get_worker_number(),
          sync_id);
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();
  // Update the work and span recorded for the bottom-most frame on the stack.

  // Add achild_work to contin_work, and reset achild_work.
  bottom.contin_work += bottom.achild_work;
  bottom.achild_work = cilk_time_t::zero();

  // Select the largest of lchild_span and contin_span, and then reset
  // lchild_span.
  if (bottom.lchild_span > bottom.contin_span)
    bottom.contin_span = bottom.lchild_span;
  bottom.lchild_span = cilk_time_t::zero();

  if (bottom.lchild_bspan > bottom.contin_bspan)
    bottom.contin_bspan = bottom.lchild_bspan;
  bottom.lchild_bspan = cilk_time_t::zero();

  stack.start.gettime();
}

///////////////////////////////////////////////////////////////////////////
// Probes and associated routines

CILKTOOL_API wsp_t wsp_getworkspan() CILKSCALE_NOTHROW {
  if (USING_CSI_SF) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

    ss.stop.gettime();

#if TRACE_CALLS
    fprintf(stderr, "getworkspan()\n");
#endif
    duration_t strand_time = ss.elapsed_time();
    shadow_stack_frame_t &bot = ss.get_bot();
    bot.contin_work += strand_time;
    bot.contin_span += strand_time;
    bot.contin_bspan += strand_time;

    wsp_t result = {bot.contin_work.get_raw_duration(),
                    bot.contin_span.get_raw_duration(),
                    bot.contin_bspan.get_raw_duration()};

    // Because of the high overhead of calling gettime(), especially compared to
    // the running time of the operations in this hook, the work and span
    // measurements appear more stable if we simply use the recorded time as the
    // new start time.
    ss.start = ss.stop;
    return result;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

#if TRACE_CALLS
  fprintf(stderr, "getworkspan()\n");
#endif

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;

  wsp_t result = {stack.peek_bot().contin_work.get_raw_duration(),
                  stack.peek_bot().contin_span.get_raw_duration(),
                  stack.peek_bot().contin_bspan.get_raw_duration()};

  // Because of the high overhead of calling gettime(), especially compared to
  // the running time of the operations in this hook, the work and span
  // measurements appear more stable if we simply use the recorded time as the
  // new start time.
  stack.start = stack.stop;

  return result;
}

__attribute__((visibility("default"))) wsp_t &
operator+=(wsp_t &lhs, const wsp_t &rhs) noexcept {
  lhs.work += rhs.work;
  lhs.span += rhs.span;
  lhs.bspan += rhs.bspan;
  return lhs;
}

__attribute__((visibility("default"))) wsp_t &
operator-=(wsp_t &lhs, const wsp_t &rhs) noexcept {
  lhs.work -= rhs.work;
  lhs.span -= rhs.span;
  lhs.bspan -= rhs.bspan;
  return lhs;
}

__attribute__((visibility("default"))) std::ostream &
operator<<(std::ostream &OS, const wsp_t &pt) {
  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;

  cilk_time_t work = cilk_time_t(pt.work);
  cilk_time_t span = cilk_time_t(pt.span);
  cilk_time_t bspan = cilk_time_t(pt.bspan);
  OS << work << ", " << span << ", " << work.get_val_d() / span.get_val_d()
     << ", " << bspan << ", " << work.get_val_d() / bspan.get_val_d();

  stack.start.gettime();
  return OS;
}

__attribute__((visibility("default"))) std::ofstream &
operator<<(std::ofstream &OS, const wsp_t &pt) {
  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;

  cilk_time_t work = cilk_time_t(pt.work);
  cilk_time_t span = cilk_time_t(pt.span);
  cilk_time_t bspan = cilk_time_t(pt.bspan);
  OS << work << ", " << span << ", " << work.get_val_d() / span.get_val_d()
     << ", " << bspan << ", " << work.get_val_d() / bspan.get_val_d();

  stack.start.gettime();
  return OS;
}

CILKTOOL_API wsp_t wsp_add(wsp_t lhs, wsp_t rhs) CILKSCALE_NOTHROW {
  lhs.work += rhs.work;
  lhs.span += rhs.span;
  lhs.bspan += rhs.bspan;
  return lhs;
}

CILKTOOL_API wsp_t wsp_sub(wsp_t lhs, wsp_t rhs) CILKSCALE_NOTHROW {
  lhs.work -= rhs.work;
  lhs.span -= rhs.span;
  lhs.bspan -= rhs.bspan;
  return lhs;
}

CILKTOOL_API void wsp_dump(wsp_t wsp, const char *tag) {
  if (USING_CSI_SF) {
    shadow_stack_top_bot_t &ss = *&tool->ss;

    ss.stop.gettime();

    duration_t strand_time = ss.elapsed_time();
    shadow_stack_frame_t &bot = ss.get_bot();
    bot.contin_work += strand_time;
    bot.contin_span += strand_time;
    bot.contin_bspan += strand_time;

    std::basic_ostream<char> &output = *tool->out_view();
    ensure_header(output);
    print_results(output, tag, cilk_time_t(wsp.work), cilk_time_t(wsp.span),
                  cilk_time_t(wsp.bspan));

    ss.start.gettime();
    return;
  }

  shadow_stack_t &stack = *&*tool->shadow_stack;

  stack.stop.gettime();

  shadow_stack_frame_t &bottom = stack.peek_bot();

  duration_t strand_time = stack.elapsed_time();
  bottom.contin_work += strand_time;
  bottom.contin_span += strand_time;
  bottom.contin_bspan += strand_time;

  std::basic_ostream<char> &output = *tool->out_view();
  ensure_header(output);
  print_results(output, tag, cilk_time_t(wsp.work), cilk_time_t(wsp.span),
                cilk_time_t(wsp.bspan));

  stack.start.gettime();
}
