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
#include <string>
#include <iostream>
#include <sstream>
#include <getopt.h>

#include <pcap/pcap.h>


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

    pcap_t* open(const std::string& iface, const std::string& file,
		 const std::string& program)
    {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* p;

	if(iface.empty()) {
	    p = pcap_open_offline(file.c_str(), errbuf);
	}
	else {
	    p = pcap_open_live(iface.c_str(), 65000,
			       0, 0, errbuf);
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
}


int main(int argc, char** argv)
{
    using std::string;

    const string prog = argv[0] ? argv[0] : "tcp";
    const string usage = string("usage: ")
	+ prog + " [-i iface | -r file] [expression]\n"
	"       "
	+ prog + " --help";
    constexpr struct option long_options[] = {
	{"help", 0, 0, 'H'},
	{0, 0, 0, 0}
    };

    std::string iface;
    std::string file;
    
    int ch;
    while((ch = getopt_long(argc, argv, "i:r:",
			    &long_options[0], 0)) != -1) {
	switch(ch) {
	case 'H':
	    std::cout << usage << '\n';
	    return 0;
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

    if(iface.empty() && file.empty()) {
	std::cerr << usage << '\n';
	return 1;
    }

    const std::string program = join(' ', argv+optind, argv+argc);

    pcap_t* p = open(iface, file, program);
    if(!p) {
	return 1;
    }

    return 0;
}
