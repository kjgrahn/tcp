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
#include <string>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <getopt.h>

#include <pcap/pcap.h>

#include "analyzer.h"

namespace {
    template <class T, class It>
    std::ostream& join(std::ostream& os, T delim, It begin, It end)
    {
	for(It i=begin; i!=end; i++) {
	    if(i!=begin) os << delim;
	    os << *i;
	}
	return os;
    }

    template <class T, class It>
    std::string join(T delim, It begin, It end)
    {
	std::ostringstream oss;
	join(oss, delim, begin, end);
	return oss.str();
    }

    pcap_t* open_live(const std::string& device, int snaplen, char* errbuf)
    {
	pcap_t* const p = pcap_create(device.c_str(), errbuf);
	if (!p) return p;

	int err;
	auto fail = [&] (const char* s) {
	    std::snprintf(errbuf, PCAP_ERRBUF_SIZE,
			  "error: %s failed with code %d",
			  s, err);
	    return nullptr;
	};

	err = pcap_set_promisc(p, 0);
	if (err) return fail("pcap_set_promisc");
	err = pcap_set_snaplen(p, snaplen);
	if (err) return fail("pcap_set_snaplen");
	err = pcap_set_immediate_mode(p, 1);
	if (err) return fail("pcap_set_immediate_mode");
	err = pcap_activate(p);
	if (err) return fail("pcap_activate");

	return p;
    }

    pcap_t* open(const std::string& iface, const std::string& file,
		 const std::string& program)
    {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* p;

	if(iface.empty()) {
	    p = pcap_open_offline(file.c_str(), errbuf);
	}
	else {
	    p = open_live(iface.c_str(), 65000, errbuf);
	}

	if(!p) {
	    std::cerr << errbuf << '\n';
	    return p;
	}

	if(!program.empty()) {
	    struct bpf_program fp;
	    int err = pcap_compile(p, &fp, program.c_str(),
				   1, PCAP_NETMASK_UNKNOWN);

	    if(!err) {
		err = pcap_setfilter(p, &fp);
	    }

	    if(err) {
		std::cerr << "'" << program << "': "
			  << pcap_geterr(p) << '\n';
		return nullptr;
	    }
	}

	return p;
    }

    unsigned to_int(const std::string& s)
    {
	const char* p = s.c_str();
	char* end;
	unsigned n = std::strtoul(p, &end, 10);
	if(*end) n = 0;
	return n;
    }
}


int main(int argc, char** argv)
{
    using std::string;

    const string prog = argv[0] ? argv[0] : "tcp";
    const string usage = string("usage: ")
	+ prog + " [-w width] [-c] [-a] [-i iface | -r file] [expression]\n"
	"       "
	+ prog + " --help\n"
	"       "
	+ prog + " --version";
    constexpr struct option long_options[] = {
	{"help",  0, 0, 'H'},
	{"version",  0, 0, 'V'},
	{"width", 1, 0, 'w'},
	{"color", 0, 0, 'c'},
	{"ascii", 0, 0, 'a'},
	{0, 0, 0, 0}
    };

    unsigned width = 80;
    bool color = false;
    bool ascii = false;
    std::string iface;
    std::string file;
    
    int ch;
    while((ch = getopt_long(argc, argv, "w:cai:r:",
			    &long_options[0], 0)) != -1) {
	switch(ch) {
	case 'H':
	    std::cout << usage << '\n';
	    return 0;
	    break;
	case 'V':
	    std::cout << "tcp 1.1\n"
		      << "Copyright (c) 2016--2025 J. Grahn\n";
	    return 0;
	    break;
	case 'w':
	    width = to_int(optarg);
	    break;
	case 'c':
	    color = true;
	    break;
	case 'a':
	    ascii = true;
	    break;
	case 'i':
	    iface = optarg;
	    file = "";
	    break;
	case 'r':
	    file = optarg;
	    iface = "";
	    break;
	case ':':
	case '?':
	    std::cerr << usage << '\n';
	    return 1;
	    break;
	default:
	    break;
	}
    }

    bool bad_args = iface.empty() && file.empty();
    bad_args |= width==0;

    if(bad_args) {
	std::cerr << usage << '\n';
	return 1;
    }

    const std::string program = join(' ', argv+optind, argv+argc);

    pcap_t* p = open(iface, file, program);
    if(!p) {
	return 1;
    }

    Analyzer analyzer(std::cout, width, color, ascii,
		      pcap_datalink(p));

    while(1) {
	struct pcap_pkthdr* head;
	const u_char* data;
	int rc = pcap_next_ex(p, &head, &data);

	if(rc==0) continue;
	if(rc==-2) break;
	if(rc==-1) {
	    std::cerr << pcap_geterr(p) << '\n';
	    break;
	}

	analyzer.feed(*head, data);
    }
    analyzer.end();

    return 0;
}
