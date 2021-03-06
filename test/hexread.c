/*
 * Copyright (c) 2012 J�rgen Grahn
 * All rights reserved.
 *
 */
#include "hexread.h"

#include <ctype.h>
#include <assert.h>


static unsigned nybble(const char ch)
{
    /* sure, I assume a sane character set */
    assert(isxdigit(ch));
    if(isdigit(ch)) return ch - '0';
    if('a' <= ch && ch <= 'f') return 10 + (ch - 'a');
    assert('A' <= ch && ch <= 'F');
    return 10 + (ch - 'A');
}


static void octet(uint8_t* const dst, const char* const src)
{
    *dst = nybble(src[0]) << 4;
    *dst |= nybble(src[1]);
}


/**
 * Decode [begin .. end) from a hex dump (e.g. "f0 00 ba 12")
 * into octet buffer 'buf', which is assumed to be large enough.
 *
 * Tolerated input is hex digits and whitespace. Any amount of whitespace
 * is ok, except it must not appear between nybbles:
 *
 *    "12 34 56" - ok
 *    "1234 56"  - also fine; same thing
 *    "123456"   - also fine
 *    "123 456"  - not ok; 0x12 is returned and "3 456" remains
 *                 unencoded
 *
 * Returns the number of octets read, and updates 'begin' to
 * the first undecoded character much like strtoul(3) does.
 */
size_t hexread(uint8_t* const buf,
	       const char** begin, const char* const end)
{
    uint8_t* q = buf;
    const char* p = *begin;
    while(p!=end && isspace(*p)) p++;

    while(end-p > 1) {
	if(!isxdigit(p[0]) || !isxdigit(p[1])) break;
	octet(q++, p);
	p += 2;
	while(p!=end && isspace(*p)) p++;
    }

    *begin = p;
    return q - buf;
}
