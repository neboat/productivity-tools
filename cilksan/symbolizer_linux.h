#ifndef _SYMBOLIZER_LINUX
#define _SYMBOLIZER_LINUX

#include "symbolizer.h"

struct ProcSelfMapsBuff {
  char *data;
  uptr mmaped_size;
  uptr len;
};

struct MemoryMappingLayoutData {
  ProcSelfMapsBuff proc_self_maps;
  const char *current;
};

#endif // _SYMBOLIZER_LINUX
