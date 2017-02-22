/* Copyright (c) 2017 Jörgen Grahn
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
#include "sequence.h"

#include "tcp.h"

Sequence::Sequence(const Tcp& tcp)
    : next(tcp.next())
{}

Sequence::Verdict Sequence::feed(const Tcp& tcp)
{
    uint32_t begin = tcp.seqno();
    uint32_t end = tcp.next();

    /* The cases are:
     *
     * ============= (existing sequence)
     *              ===== normal case
     *              ..=== hole
     *           ======== overlap
     *        ======      duplication
     *      ======..      duplication
     *
     * It's done modulo uint32_t, but let's ignore that.  The normal
     * case is covered, and getting the others wrong just at the 4 GB
     * border is rare and fairly harmless.
     */
    if(begin==next) {
	next = end;
	return Verdict::NORMAL;
    }
    if(begin > next) {
	next = end;
	return Verdict::HOLE;
    }
    if(begin < next && next < end) {
	next = end;
	return Verdict::OVERLAP;
    }
    return Verdict::DUPLICATE;
}
