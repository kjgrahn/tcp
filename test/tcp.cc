/*
 * Copyright (c) 2017 Jörgen Grahn
 * All rights reserved.
 *
 */
#include <tcp.h>
#include <hexdump.h>

#include <orchis.h>
#include <sstream>
#include <ctime>
#include <cassert>

#include "hexread.h"


namespace {

    struct Hex {
	explicit Hex(const std::string& s)
	{
	    uint8_t buf[1000];
	    const char* p = s.data();
	    const char* const q = p + s.size();
	    const unsigned n = hexread(buf, &p, q);
	    v = std::vector<uint8_t>(buf, buf + n);
	}

	Range range() const
	{
	    const auto* p = v.data();
	    return Range{p, p + v.size()};
	}

	std::vector<uint8_t> v;
    };

    std::string dump(const Range& r)
    {
	char buf[1000];
	hexdump(buf, sizeof buf, r.begin(), r.end());
	return buf;
    }

    void assert_data(const Tcp& tcp, const std::string& s)
    {
	const Hex ref{s};
	orchis::assert_eq(dump(Range(tcp.begin(), tcp.end())),
			  dump(ref.range()));
    }
}


namespace segment {

    using namespace orchis;

    void simple(TC)
    {
	const Hex v("b9f2 0009" // source/destination ports
		    "00000010 203ed424"
		    "5018 00e5" // data offset, flags, etc
		    "ffff 0000"
		    "736d 6563 6b0a");
	const Tcp t{v.range()};

	assert_true(t.valid());
	assert_true(t.client());
	assert_eq(t.src_dst(), "47602 ->     9");
	assert_false(t.has_flag());

	assert_eq(t.seqno(), 0x10);
	assert_eq(t.next(), t.seqno() + 6);

	assert_data(t, "736d 6563 6b0a");
    }

    void options(TC)
    {
	const Hex v("b9f2 0009"
		    "00000010 203ed424"
		    "7018 00e5"
		    "ffff 0000"
		    "ccccdddd eeeeffff"
		    "736d 6563 6b0a");
	const Tcp t{v.range()};

	assert_true(t.valid());
	assert_true(t.client());
	assert_eq(t.src_dst(), "47602 ->     9");
	assert_false(t.has_flag());

	assert_eq(t.seqno(), 0x10);
	assert_eq(t.next(), t.seqno() + 6);

	assert_data(t, "736d 6563 6b0a");
    }

    void seqno_wrap(TC)
    {
	const Hex v("b9f2 0009"
		    "fffffffe 203ed424"
		    "5018 00e5"
		    "ffff 0000"
		    "736d 6563 6b0a d2b8 26d4");
	const Tcp t{v.range()};

	assert_true(t.valid());
	assert_true(t.client());
	assert_eq(t.src_dst(), "47602 ->     9");
	assert_false(t.has_flag());

	assert_eq(t.seqno(), 0xfffffffe);
	assert_eq(t.next(), 0x8);

	assert_data(t, "736d 6563 6b0a d2b8 26d4");
    }

    void empty(TC)
    {
	const Hex v("b9f2 0009"
		    "00000010 203ed424"
		    "5010 00e5"
		    "ffff 0000");
	const Tcp t{v.range()};

	assert_true(t.valid());
	assert_true(t.client());
	assert_eq(t.src_dst(), "47602 ->     9");
	assert_false(t.has_flag());

	assert_eq(t.seqno(), 0x10);
	assert_eq(t.next(), t.seqno());
	assert_data(t, "");
    }

    void syn(TC)
    {
	const Hex v("b9f2 0009"
		    "00000010 203ed424"
		    "5012 00e5"
		    "ffff 0000");
	const Tcp t{v.range()};

	assert_true(t.valid());
	assert_true(t.client());
	assert_eq(t.src_dst(), "47602 ->     9");
	assert_true(t.has_flag());
	assert_eq(t.flag_desc(), "SYN");

	assert_eq(t.seqno(), 0x10);
	assert_eq(t.next(), 0x11);
	assert_data(t, "");
    }

    void data_fin(TC)
    {
	const Hex v("b9f2 0009"
		    "00000010 203ed424"
		    "5011 00e5"
		    "ffff 0000"
		    "69");
	const Tcp t{v.range()};

	assert_true(t.valid());
	assert_true(t.client());
	assert_eq(t.src_dst(), "47602 ->     9");
	assert_true(t.has_flag());
	assert_eq(t.flag_desc(), "FIN");

	assert_eq(t.seqno(), 0x10);
	assert_eq(t.next(), 0x12);
	assert_data(t, "69");
    }
}
