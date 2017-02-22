/*
 * Copyright (c) 2016, 2017 Jörgen Grahn
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "tcp.h"

#include <cstdio>

Tcp::Tcp(Range p)
    : payload(p)
{
    src = payload.eat16();
    dst = payload.eat16();
    seq_no = payload.eat32();
    payload.pop(4);
    unsigned drf = payload.eat16();
    unsigned offset = drf>>12;
    flags = drf & 0x3f;

    payload.pop(offset * 4 - 4 - 8 - 2);
}

std::string Tcp::src_dst() const
{
    char buf[20];
    std::sprintf(buf, "%5u -> %5u", src, dst);
    return buf;
}

unsigned Tcp::key() const
{
    return (src << 16) + dst;
}

/**
 * If has_flag(), return a description of the flags. It's only three
 * we care about: SYN, FIN and RST.
 */
const char* Tcp::flag_desc() const
{
    if(flags & 0x01) return "FIN";
    if(flags & 0x02) return "SYN";
    if(flags & 0x04) return "RST";
    return "";
}

/**
 * The next expected sequence number, based on this sequence
 * number and the flags and data content.
 */
unsigned Tcp::next() const
{
    unsigned n = seqno() + payload.size();
    switch(flags & 7) {
    case 0:
	break;
    case 1:
    case 2:
    case 4:
	n++;
	break;
    case 3:
    case 5:
    case 6:
	n+=2;
	break;
    case 7:
	n+=3;
    }

    return n & 0xffffffff;
}
