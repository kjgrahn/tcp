/*
 * Copyright (c) 2016, 2017 J�rgen Grahn
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
#include "analyzer.h"

#include "hexdump.h"
#include "timeval.h"
#include "packet.h"
#include "tcp.h"

#include <iostream>

#include <pcap/pcap.h>

Analyzer::Analyzer(std::ostream& os, unsigned width, bool color, bool ascii,
		   int link)
    : output(os, width, color, ascii),
      link(link)
{}

void Analyzer::feed(const pcap_pkthdr& head,
		    const u_char* data)
{
    const Range frame{head, data};
    if(frame.empty()) return;

    const Range payload = tcp(link, frame);
    if(payload.empty()) return;

    const Tcp segment{payload};
    if(!segment.valid()) return;

    feed(head, segment);
}

void Analyzer::feed(const pcap_pkthdr& head,
		    const Tcp& segment)
{
    const auto& key = segment.key();
    auto it = seqs.find(key);
    if (it==std::end(seqs)) {
	seqs.emplace(key, Sequence{segment});
    }
    else {
	Sequence::Verdict v = it->second.feed(segment);
	if(v) {
	    output.write(segment.client(), head.ts,
			 segment.src_dst(),
			 v);
	    return;
	}
    }

    if(!segment.empty()) {
	output.write(segment.client(), head.ts,
		     segment.src_dst(),
		     segment.begin(), segment.end());
    }

    if(segment.has_flag()) {
	output.write(segment.client(), head.ts,
		     segment.src_dst(),
		     segment.flag_desc());
    }
}

void Analyzer::end()
{}
