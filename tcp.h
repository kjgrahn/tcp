/* -*- c++ -*-
 *
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
#ifndef TCP_TCP_H
#define TCP_TCP_H

#include "packet.h"
#include <string>

/**
 * A possible TCP segment, found in IP payload known to be TCP.
 */
class Tcp {
public:
    explicit Tcp(Range payload);

    bool valid() const { return true; }

    bool client() const { return src > dst; }
    std::string src_dst() const;
    unsigned key() const;

    bool has_flag() const { return flags & 7; }
    const char* flag_desc() const;

    unsigned seqno() const { return seq_no; }
    unsigned next() const;

    const uint8_t* begin() const { return payload.begin(); }
    const uint8_t* end() const { return payload.end(); }
    bool empty() const { return payload.empty(); }

private:
    Range payload;
    unsigned src;
    unsigned dst;
    unsigned seq_no;
    unsigned flags;
};

#endif
