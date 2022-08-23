/// -*- C++ -*-
#ifndef INCLUDED_SHADOW_STACK_H
#define INCLUDED_SHADOW_STACK_H

#include "cilkscale_timer.h"

#ifndef SERIAL_TOOL
#define SERIAL_TOOL 1
#endif

#ifndef TRACE_CALLS
#define TRACE_CALLS 0
#endif

#ifndef DEFAULT_STACK_SIZE
#define DEFAULT_STACK_SIZE 64
#endif

// Enum for types of frames
enum class frame_type
  {
   NONE,
   MAIN,
   SPAWNER,
   HELPER,
  };

// Type for a shadow stack frame
struct shadow_stack_frame_t {
  // Sum of work of all outstanding spawned children of this function observed
  // so far
  cilk_time_t achild_work = cilk_time_t::zero();
  // Work of the continuation of the function since the spawn of its longest
  // child
  cilk_time_t contin_work = cilk_time_t::zero();

  // Longest span of an outstanding spawned child of this function observed so
  // far
  cilk_time_t lchild_span = cilk_time_t::zero();
  // Span of the continuation of the function since the spawn of its longest
  // child
  cilk_time_t contin_span = cilk_time_t::zero();

  // Longest span of an outstanding spawned child of this function observed so
  // far
  cilk_time_t lchild_bspan = cilk_time_t::zero();
  // Span of the continuation of the function since the spawn of its longest
  // child
  cilk_time_t contin_bspan = cilk_time_t::zero();

  // Function type
  frame_type type = frame_type::NONE;

  // Initialize the stack frame. 
  void init(frame_type _type, cilk_time_t p_contin_work = cilk_time_t::zero(),
            cilk_time_t p_contin_span = cilk_time_t::zero(),
            cilk_time_t p_contin_bspan = cilk_time_t::zero()) {
    type = _type;
    achild_work = cilk_time_t::zero();
    contin_work = p_contin_work;
    lchild_span = cilk_time_t::zero();
    contin_span = p_contin_span;
    lchild_bspan = cilk_time_t::zero();
    contin_bspan = p_contin_bspan;
  }
};

struct shadow_stack_top_bot_t {
  // Start and stop timers for measuring the execution time of a strand.
  cilkscale_timer_t start;
  cilkscale_timer_t stop;

  // Top and bottom stack frames.
  shadow_stack_frame_t top;
  shadow_stack_frame_t *bot;

  shadow_stack_top_bot_t(frame_type type = frame_type::MAIN) {
    top.init(type);
    bot = &top;
  }
  shadow_stack_top_bot_t(const shadow_stack_top_bot_t &copy) : top(copy.top) {
    if (copy.bot == &copy.top)
      bot = &top;
    else
      bot = copy.bot;
  }

  shadow_stack_frame_t &get_top() { return top; }
  shadow_stack_frame_t &get_bot() const { return *bot; }
  void set_bot(shadow_stack_frame_t &frame) { bot = &frame; }

  /// Reducer support

  static void identity(void *view) {
    new (view) shadow_stack_top_bot_t(frame_type::SPAWNER);
  }

  static void reduce(void *left_view, void *right_view) {
    shadow_stack_top_bot_t *left =
        static_cast<shadow_stack_top_bot_t *>(left_view);
    shadow_stack_top_bot_t *right =
        static_cast<shadow_stack_top_bot_t *>(right_view);

    shadow_stack_frame_t &l_bot = *left->bot;
    shadow_stack_frame_t &r_bot = *right->bot;

    assert(frame_type::SPAWNER == r_bot.type);
    assert(right->bot == &right->top);

#if TRACE_CALLS
    fprintf(stderr, "left contin_work = %ld\nleft achild_work = %ld\n"
            "right contin_work = %ld\nright achild_work = %ld\n",
            l_bot.contin_work, l_bot.achild_work,
            r_bot.contin_work, r_bot.achild_work);
    fprintf(stderr, "left contin = %ld\nleft child = %ld\n"
            "right contin = %ld\nright child = %ld\n",
            l_bot.contin_span, l_bot.lchild_span,
            r_bot.contin_span, r_bot.lchild_span);
    fprintf(stderr, "left contin bspan = %ld\nleft child bspan = %ld\n"
            "right contin bspan = %ld\nright child bspan = %ld\n",
            l_bot.contin_bspan, l_bot.lchild_bspan,
            r_bot.contin_bspan, r_bot.lchild_bspan);
#endif

    // Add the work variables from the right stack into the left.
    l_bot.contin_work += r_bot.contin_work;
    l_bot.achild_work += r_bot.achild_work;

    // If the left stack has a longer path from the root to the end of its
    // longest child, set this new span in keft.
    if (l_bot.contin_span + r_bot.lchild_span > l_bot.lchild_span) {
      l_bot.lchild_span = l_bot.contin_span + r_bot.lchild_span;
    }
    // Add the continuation span from the right stack into the left.
    l_bot.contin_span += r_bot.contin_span;

    // If the left stack has a longer path from the root to the end of its
    // longest child, set this new span in keft.
    if (l_bot.contin_bspan + r_bot.lchild_bspan > l_bot.lchild_bspan) {
      l_bot.lchild_bspan = l_bot.contin_bspan + r_bot.lchild_bspan;
    }
    // Add the continuation span from the right stack into the left.
    l_bot.contin_bspan += r_bot.contin_bspan;

    right->~shadow_stack_top_bot_t();
  }

  duration_t elapsed_time() {
    return ::elapsed_time(&stop, &start);
  }
};

using stack_index_t = int32_t;

// Type for a shadow stack
struct shadow_stack_t {
  // Start and stop timers for measuring the execution time of a strand.
  cilkscale_timer_t start;
  cilkscale_timer_t stop;

private:
  // Dynamic array of shadow-stack frames.
  shadow_stack_frame_t *frames;
  stack_index_t capacity;

  // Index of the shadow-stack frame for the function/task frame at the bottom
  // of the stack.
  stack_index_t bot = 0;

public:
  shadow_stack_t(frame_type type = frame_type::MAIN) {
    frames = new shadow_stack_frame_t[DEFAULT_STACK_SIZE];
    capacity = DEFAULT_STACK_SIZE;
    frames[0].init(type);
  }

  shadow_stack_t(const shadow_stack_t &copy) : capacity(copy.capacity),
                                               bot(copy.bot) {
    frames = new shadow_stack_frame_t[capacity];
    for (stack_index_t i = 0; i <= bot; ++i)
      frames[i] = copy.frames[i];
  }

  ~shadow_stack_t() {
    if (frames)
      delete[] frames;
  }

  // For debugging
  stack_index_t bot_index() const { return bot; }

  shadow_stack_frame_t &peek_bot() const {
    assert(frames && "frames not allocated");
    return frames[bot];
  }

  shadow_stack_frame_t &push(frame_type type,
                             cilk_time_t p_contin_work = cilk_time_t::zero(),
                             cilk_time_t p_contin_span = cilk_time_t::zero(),
                             cilk_time_t p_contin_bspan = cilk_time_t::zero()) {
    ++bot;

    // If necessary, double the capacity of the shadow stack.
    if (bot >= capacity) {
      // Save the old shadow stack.
      stack_index_t old_capacity = capacity;
      shadow_stack_frame_t *old_frames = frames;

      // Allocate a new shadow stack of twice the capacity.
      capacity *= 2;
      frames = new shadow_stack_frame_t[capacity];

      // Copy the old stack into the new.
      for (stack_index_t i = 0; i < old_capacity; ++i)
        frames[i] = old_frames[i];

      // Delete the old stack.
      delete[] old_frames;
    }

    frames[bot].init(type, p_contin_work, p_contin_span, p_contin_bspan);
    return frames[bot];
  }

  shadow_stack_frame_t &pop() {
    assert(bot > 0 && "Pop from empty shadow stack.");
    shadow_stack_frame_t &old_bottom = frames[bot];
    --bot;
    return old_bottom;
  }

  /// Reducer support

  static void identity(void *view) {
    new (view) shadow_stack_t(frame_type::SPAWNER);
  }

  static void reduce(void *left_view, void *right_view) {
    shadow_stack_t *left = static_cast<shadow_stack_t *>(left_view);
    shadow_stack_t *right = static_cast<shadow_stack_t *>(right_view);

    shadow_stack_frame_t &l_bot = left->peek_bot();
    shadow_stack_frame_t &r_bot = right->peek_bot();

    assert(frame_type::SPAWNER == r_bot.type);
    assert(0 == right->bot_index());

#if TRACE_CALLS
    fprintf(stderr, "left contin_work = %ld\nleft achild_work = %ld\n"
            "right contin_work = %ld\nright achild_work = %ld\n",
            l_bot.contin_work, l_bot.achild_work,
            r_bot.contin_work, r_bot.achild_work);
    fprintf(stderr, "left contin = %ld\nleft child = %ld\n"
            "right contin = %ld\nright child = %ld\n",
            l_bot.contin_span, l_bot.lchild_span,
            r_bot.contin_span, r_bot.lchild_span);
    fprintf(stderr, "left contin bspan = %ld\nleft child bspan = %ld\n"
            "right contin bspan = %ld\nright child bspan = %ld\n",
            l_bot.contin_bspan, l_bot.lchild_bspan,
            r_bot.contin_bspan, r_bot.lchild_bspan);
#endif

    // Add the work variables from the right stack into the left.
    l_bot.contin_work += r_bot.contin_work;
    l_bot.achild_work += r_bot.achild_work;

    // If the left stack has a longer path from the root to the end of its
    // longest child, set this new span in keft.
    if (l_bot.contin_span + r_bot.lchild_span > l_bot.lchild_span) {
      l_bot.lchild_span = l_bot.contin_span + r_bot.lchild_span;
    }
    // Add the continuation span from the right stack into the left.
    l_bot.contin_span += r_bot.contin_span;

    // If the left stack has a longer path from the root to the end of its
    // longest child, set this new span in keft.
    if (l_bot.contin_bspan + r_bot.lchild_bspan > l_bot.lchild_bspan) {
      l_bot.lchild_bspan = l_bot.contin_bspan + r_bot.lchild_bspan;
    }
    // Add the continuation span from the right stack into the left.
    l_bot.contin_bspan += r_bot.contin_bspan;

    right->~shadow_stack_t();
  }

  duration_t elapsed_time() {
    return ::elapsed_time(&stop, &start);
  }
};

typedef shadow_stack_t _Hyperobject(shadow_stack_t::identity,
                                    shadow_stack_t::reduce)
  shadow_stack_reducer;

typedef shadow_stack_top_bot_t
    _Hyperobject(shadow_stack_top_bot_t::identity,
                 shadow_stack_top_bot_t::reduce) shadow_stack_top_bot_reducer;

#endif
