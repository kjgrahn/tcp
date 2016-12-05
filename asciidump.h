/*
 * Copyright (c) 2016 Jörgen Grahn.
 * All rights reserved.
 *
 */
#ifndef TCP_ASCIIDUMP_H
#define TCP_ASCIIDUMP_H
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

const void* asciidump(char* buf, size_t count,
		      const void* begin, const void* end);

#ifdef __cplusplus
}
#endif
#endif
