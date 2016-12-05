/*
 * Copyright (c) 2016 Jörgen Grahn
 * All rights reserved.
 *
 */
#include "asciidump.h"

#include <stdint.h>
#include <ctype.h>


static const uint8_t* dump(char* buf, size_t size,
			   const uint8_t* const begin,
			   const uint8_t* const end)
{
    const uint8_t* p = begin;

    while(size>1 && p!=end) {
	char ch = isprint(*p)? *p : '.';
	*buf++ = ch;
	size--;
	p++;
    }
    *buf++ = '\0';
    return p;
}


/**
 * Format [begin .. end) as ASCII, with anything but isprint()able
 * octets printed as '.', as much of it
 * which fits in 'buf', of size 'size'.  'size' must
 * allow room for the '\0' terminator (for example, be
 * non-zero).
 *
 * Returns the first octet not formatted.
 *
 * This way, you can e.g. specify a buffer of 3*8 characters,
 * loop until hexdump() returns 'end', printing the buffer + '\n'
 * at every iteration -- and you have a hexdump with 8 octets
 * per line.
 *
 */
const void* asciidump(char* buf, size_t size,
		      const void* begin, const void* end)
{
    return dump(buf, size, begin, end);
}
