/// -*- C++ -*-
#ifndef INCLUDED_SHADOW_STACK_H
#define INCLUDED_SHADOW_STACK_H

#include "cilkscale_timer.h"

#ifndef SERIAL_TOOL
#define SERIAL_TOOL 1
#endif

#include <cilk/cilk_api.h>
#if !SERIAL_TOOL
#include <cilk/reducer.h>
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
  // Work of the continuation of the function since the spawn of its longest
  // child
  cilk_time_t contin_work = cilk_time_t::zero();
  // Span of the continuation of the function since the spawn of its longest
  // child
  cilk_time_t contin_span = cilk_time_t::zero();
  // Span of the continuation of the function since the spawn of its longest
  // child
  cilk_time_t contin_bspan = cilk_time_t::zero();

  // Sum of work of all outstanding spawned children of this function observed
  // so far
  cilk_time_t achild_work = cilk_time_t::zero();

  // Longest span of an outstanding spawned child of this function observed so
  // far
  cilk_time_t lchild_span = cilk_time_t::zero();

  // Longest span of an outstanding spawned child of this function observed so
  // far
  cilk_time_t lchild_bspan = cilk_time_t::zero();

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
    contin_bspan = p_contin_span;
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
  shadow_stack_top_bot_t(shadow_stack_top_bot_t &&move)
      : top(std::move(move.top))// , bot(std::move(move.bot))
  {
    if (move.bot == &move.top)
      bot = &top;
    else
      bot = std::move(move.bot);
  }

#if !SERIAL_TOOL
  // Move-in constructor
  shadow_stack_top_bot_t(cilk::move_in_wrapper<shadow_stack_top_bot_t> w) {
    top = w.value().top;
    if (w.value().bot == &w.value().top)
      bot = &top;
    else
      bot = w.value().bot;
  }
#endif

  shadow_stack_frame_t &get_top() { return top; }
  shadow_stack_frame_t &get_bot() const { return *bot; }
  void set_bot(shadow_stack_frame_t &frame) { bot = &frame; }

  /// Reducer support

  void move_in(shadow_stack_top_bot_t &&v) {
    top = std::move(v.top);
    bot = std::move(v.bot);
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
  shadow_stack_t(shadow_stack_t &&move)
      : frames(std::move(move.frames)), capacity(std::move(move.capacity)),
        bot(std::move(move.bot))
  {}

#if !SERIAL_TOOL
  // Move-in constructor
  shadow_stack_t(cilk::move_in_wrapper<shadow_stack_t> w) {
    capacity = w.value().capacity;
    frames = w.value().frames;
    bot = w.value().bot;
  }
#endif

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

  void move_in(shadow_stack_t &&v) {
    capacity = std::move(v.capacity);
    frames = std::move(v.frames);
    bot = std::move(v.bot);
    v.frames = nullptr;
  }
};

#endif
