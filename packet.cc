/*
 * Copyright (c) 2016 Jörgen Grahn
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
#include "packet.h"

#include <net/ethernet.h>

namespace {
    unsigned get16(const u_char* p)
    {
	unsigned n = *p++;
	n = (n<<8) + *p;
	return n;
    }
}


Range::Range(const pcap_pkthdr& head,
	     const u_char* data)
    : a(data),
      b(data + head.len)
{
    if(head.caplen < head.len) {
	// ignore incompletely captured frames
	b = a;
    }
}

unsigned Range::eat16()
{
    unsigned n = get16(a);
    pop(2);
    return n;
}

unsigned Range::eat32()
{
    unsigned n = eat16();
    n <<= 16;
    n |= eat16();
    return n;
}

/**
 * Stripping the link-layer from a frame; extracting IPv4/IPv6,
 * or returning an empty range.
 */
Range unlink(int linktype, Range frame)
{
    switch(linktype) {
    case DLT_EN10MB: {
	frame.pop(6 + 6);
	auto etype = frame.eat16();
	if(etype==ETHERTYPE_VLAN) {
	    frame.pop(2);
	    etype = frame.eat16();
	}
	switch(etype) {
	case ETHERTYPE_IP:
	case ETHERTYPE_IPV6:
	    break;
	default:
	    frame.clear();
	    break;
	}
	break;
    }
    case DLT_RAW:
	break;
    default:
	frame.clear();
	break;
    }

    return frame;
}


/**
 * Stripping everything but the TCP content, if any.
 */
Range tcp(int linktype, Range frame)
{
    frame = unlink(linktype, frame);
    if(frame.empty()) return frame;

    auto p = frame.begin();
    unsigned version = (*p) >> 4;
    if(version==4) {
	unsigned ihl = *p & 0x0f;
	p += 2;
        unsigned totlen = get16(p);
	p += 4;
	unsigned frag = get16(p);
	if(frag & 0x3fff) {
	    return frame.clear();
	}
	p += 3;
	unsigned proto = *p;
	if(proto != 6) {
	    return frame.clear();
	}

        frame.trim(totlen);
	frame.pop(4 * ihl);
	return frame;
    }
    else if(version==6) {
	frame.pop(4);
	unsigned plen = frame.eat16();
	unsigned nh = frame.eat8();
	frame.pop(1 + 8*4);
	// lame implementation
	if(nh!=6) {
	    return frame.clear();
	}

	frame.trim(plen);
	return frame;
    }
    else {
	return frame.clear();
    }
}
