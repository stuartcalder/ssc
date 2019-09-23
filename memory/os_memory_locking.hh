/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include <cstdlib>
#include <cstdio>

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>

extern "C" {
#if defined(__Unix_Like__)
#	define __SSC_memlocking__	1
#	include <sys/mman.h>
#else
#	error	"Only implemented on Unix-like systems."
#endif
}/* extern "C" */

namespace ssc {
	inline void
	lock_os_memory (void const *addr, size_t const length) {
#if defined(__Unix_Like__)
		if (mlock( addr, length ) != 0) {
			std::fputs( "Error: Failed to mlock()\n", stderr );
			std::exit( EXIT_FAILURE );
		}
#else
#	error	"lock_memory only implemented on unix-like operating systems."
#endif
	}/* lock_memory */

	inline void
	unlock_os_memory (void const *addr, size_t const length) {
#if defined(__Unix_Like__)
		if (munlock( addr, length ) != 0) {
			std::fputs( "Error: Failed to munlock()\n", stderr );
			std::exit( EXIT_FAILURE );
		}
#else
#	error	"unlock_memory only implemented on unix-like operating systems."
#endif
	}/* unlock_memory */
}/* ! namespace ssc */
