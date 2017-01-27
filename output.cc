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
#include "output.h"

#include "timeval.h"
#include "hexdump.h"
#include "asciidump.h"

#include <iostream>


Color::Color(bool color)
    : reset(color? "\033[0m" : "")
{}

const char* Color::operator() (bool client) const
{
    if(!reset[0]) return "";
    return client? "\033[0;33m" : "\033[0;32m";
}


namespace {
    unsigned inner(unsigned width)
    {
	// 23:55:05.235    22 -> 39602  nn ...
	// -----12----- ------14------  ---
	unsigned headwidth = 12+1+14+2;
	width = std::max(width, headwidth + 3);
	return width - headwidth;
    }
}

Output::Output(std::ostream& os, unsigned width,
	       bool color, bool ascii)
    : os(os),
      bufv(inner(width)),
      color(color),
      ascii(ascii)
{}

void Output::write(bool client, const timeval& tv,
		   const std::string& peers,
		   const std::string& flags)
{
    os << tv << ' '
       << color(client) << peers << "  "
       << flags << color.reset << std::endl;
}

void Output::write(bool client, const timeval& tv,
		   const std::string& peers,
		   const void* const begin,
		   const void* const end)
{
    const void* p = begin;
    char* const buf = bufv.data();

    auto dump = [this, buf, end](const void* p) {
        if(ascii) {
	    return asciidump(buf, bufv.size(), p, end);
	}
	else {
	    return hexdump(buf, bufv.size(), p, end);
	}
    };

    p = dump(p);

    os << tv << ' '
       << color(client) << peers << "  "
       << buf << '\n';

    while(p!=end) {
	p = dump(p);
	os << "                             "
	   << buf << '\n';
    }

    os << color.reset << std::flush;
}
