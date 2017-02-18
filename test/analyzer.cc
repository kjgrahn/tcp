/*
 * Copyright (c) 2016 Jörgen Grahn
 * All rights reserved.
 *
 */
#include <analyzer.h>

#include <orchis.h>
#include <sstream>
#include <ctime>
#include <cassert>

#include "hexread.h"


namespace {

    void feed(Analyzer& a, const std::string& data)
    {
	u_char buf[1000];
	const char* p = data.data();
	const char* const q = p + data.size();
	const unsigned n = hexread(buf, &p, q);

	const pcap_pkthdr h = {{0, 0}, n, n};

	a.feed(h, buf);
    }

    void erase_timestamp(std::string& s)
    {
	s.erase(0, 13);
    }

    void assert_read(std::istream& is, const std::string& ref)
    {
	std::string s;
	orchis::assert_true(std::getline(is, s));
	erase_timestamp(s);
	orchis::assert_eq(s, ref);
    }

    void assert_eof(std::istream& is)
    {
	std::string s;
	orchis::assert_false(std::getline(is, s));
    }
}


namespace analyzer {

    namespace link {
	constexpr auto ref = "47602 ->     9  73 6d 65 63 6b 0a";

	void ethernet(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_EN10MB};

	    feed(a,
		 "000d 9360 7e78 0030 05d0 c6bb 0800"
		 "4500 002e"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009" // source/destination ports
		 "0d3d986c 203ed424"
		 "5018 00e5" // data offset, flags, etc
		 "50e5 0000"
		 "736d 6563 6b0a" // tcp payload
		 "d2b8 26d4");

	    feed(a,
		 "000d 9360 7e78 0030 05d0 c6bb 0800"
		 "4500 002e"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_read(ss, ref);
	    assert_read(ss, ref);
	    assert_eof(ss);
	}

	void vlan(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_EN10MB};

	    feed(a,
		 "000d 9360 7e78 0030 05d0 c6bb 8100"
		 "0000 0800"
		 "4500 002e"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_read(ss, ref);
	    assert_eof(ss);
	}

	void raw(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4500 002e"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_read(ss, ref);
	    assert_eof(ss);
	}
    }

    namespace ip {
	constexpr auto ref = "47602 ->     9  73 6d 65 63 6b 0a";
	
	void options(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4700 0036"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "aaaaaaaa aaaaaaaa"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_read(ss, ref);
	    assert_eof(ss);
	}

	void fragment(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4500 002e"
		 "d56b 2000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    feed(a,
		 "4500 002e"
		 "d56b 0001"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_eof(ss);
	}

	void v6(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "6000 0000"
		 "001a 0600"
		 "00000000 00000000 00000000 00000001"
		 "00000000 00000000 00000000 00000001"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_read(ss, ref);
	    assert_eof(ss);
	}

	void proto(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4500 002e"
		 "d56b 4000"
		 "4011 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    feed(a,
		 "6000 0000"
		 "001a 1100"
		 "00000000 00000000 00000000 00000001"
		 "00000000 00000000 00000000 00000001"
		 "b9f2 0009"
		 "0d3d986c 203ed424"
		 "5018 00e5"
		 "50e5 0000"
		 "736d 6563 6b0a");

	    assert_eof(ss);
	}
    }

    namespace tcp {
	void push(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4500 002d"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "5018 0000"
		 "aaaa 0000"
		 "ff6d 6563 6b");

	    assert_read(ss, "65535 ->     9  ff 6d 65 63 6b");
	    assert_eof(ss);
	}

	void options(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4500 0031"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "6018 0000"
		 "aaaa 0000"
		 "aaaa aaaa"
		 "ff6d 6563 6b");

	    assert_read(ss, "65535 ->     9  ff 6d 65 63 6b");
	    assert_eof(ss);
	}

	void flags(orchis::TC)
	{
	    std::stringstream ss;
	    Analyzer a{ss, 1000, false, false, DLT_RAW};

	    feed(a,
		 "4500 0028"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "5011 0000"
		 "aaaa 0000");
	    assert_read(ss, "65535 ->     9  FIN");

	    feed(a,
		 "4500 0028"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "5012 0000"
		 "aaaa 0000");
	    assert_read(ss, "65535 ->     9  SYN");

	    feed(a,
		 "4500 0028"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "5014 0000"
		 "aaaa 0000");
	    assert_read(ss, "65535 ->     9  RST");

	    feed(a,
		 "4500 0028"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "5010 0000"
		 "aaaa 0000");

	    feed(a,
		 "4500 0028"
		 "d56b 4000"
		 "4006 27f3"
		 "c0a8de0a"
		 "c0a8de03"
		 "ffff 0009"
		 "00000000 00000000"
		 "5000 0000"
		 "aaaa 0000");

	    assert_eof(ss);
	}
    }
}
