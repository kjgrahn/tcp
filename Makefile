# Makefile
#
# Copyright (c) 2016 Jörgen Grahn
# All rights reserved.

SHELL=/bin/bash

all: tcp
all: test/test

INSTALLBASE=/usr/local

libtcp.a: analyzer.o
libtcp.a: timeval.o
libtcp.a: hexdump.o
	$(AR) -r $@ $^

tcp: main.o libtcp.a
	$(CXX) $(CXXFLAGS) -o $@ $< -L. -ltcp -lpcap

CFLAGS=-W -Wall -pedantic -ansi -g -Os
CXXFLAGS=-Wextra -Wall -pedantic -std=c++11 -g -Os

.PHONY: check checkv
check: test/test
	./test/test
checkv: test/test
	valgrind -q ./test/test -v

test/libtest.a: test/hexdump.o
	$(AR) -r $@ $^

test/%.o: CPPFLAGS+=-I.

test/test.cc: test/libtest.a
	orchis -o $@ $^

test/test: test/test.o test/libtest.a libtcp.a
	$(CXX) $(CXXFLAGS) -o $@ test/test.o -Ltest/ -ltest -L. -ltcp

.PHONY: install
install: all
	install -m555 tcp $(INSTALLBASE)/bin/
	install -m644 tcp.1 $(INSTALLBASE)/man/man1/

.PHONY: tags
tags: TAGS
TAGS:
	etags *.{c,h,cc}

.PHONY: depend
depend:
	makedepend -- $(CFLAGS) -- -Y -I. *.{c,cc} test/*.cc

.PHONY: clean
clean:
	$(RM) tcp
	$(RM) *.o lib*.a
	$(RM) test/test test/test.cc test/*.o test/lib*.a

love:
	@echo "not war?"

$(shell mkdir -p dep/test)
DEPFLAGS=-MT $@ -MMD -MP -MF dep/$*.Td
COMPILE.cc=$(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.c=$(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

%.o: %.cc
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	@mv dep/$*.{Td,d}

%.o: %.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	@mv dep/$*.{Td,d}

dep/%.d: ;
dep/test/%.d: ;
-include dep/*.d
-include dep/test/*.d
