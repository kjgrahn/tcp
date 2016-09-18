/* -*- c++ -*-
 *
 * Copyright (c) 2016 J�rgen Grahn
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
#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include <cstdint>
#include <algorithm>

#include <pcap/pcap.h>


class Range {
public:
    Range(const uint8_t* a, const uint8_t* b)
	: a(a), b(b)
    {}
    Range(const pcap_pkthdr& head,
	  const u_char* data);

    void clear() {
	a = b = nullptr;
    }
    void pop(size_t n) {
	a += n;
	a = std::min(a, b);
    }
    unsigned eat8() { return *a++; }
    unsigned eat16();

    const uint8_t* begin() const { return a; }
    const uint8_t* end() const { return b; }
    bool empty() const { return a==b; }

private:
    const uint8_t* a;
    const uint8_t* b;
};

Range unlink(int linktype, Range frame);
Range tcp(int linktype, Range frame);

#endif
