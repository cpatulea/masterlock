#include <stdio.h>

#ifndef RELEASE
#include <assert.h>
#else
#define assert(c) if (!(c)) { \
    fprintf(stderr, "Error %d.\n", kFileId * 1000 + __LINE__); \
    abort(); \
  }
#endif
