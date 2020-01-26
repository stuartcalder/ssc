/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include <ssc/general/symbols.hh>

#ifndef ENABLE_MEMORYLOCKING
	// Memory-lock on all supported operating systems, for prudence.
#	if    defined (__UnixLike__) || defined (__Win64__)
#		define ENABLE_MEMORYLOCKING
#	endif
#else
#	error 'Already defined'
#endif

// If __SSC_DISABLE_MEMORYLOCKING is defined, do not support memory locking.
#if    defined (ENABLE_MEMORYLOCKING) && !defined (__SSC_DISABLE_MEMORYLOCKING)
// If this macro is defined, consider memory locking to be supported.
#	ifndef __SSC_MemoryLocking__
#		define __SSC_MemoryLocking__
#	else
#		error 'Already defined'
#	endif

#	include <cstdlib>
#	include <ssc/general/integers.hh>
#	include <ssc/general/error_conditions.hh>

// Get OS-specific headers needed for locking memory.
#	if   defined (__UnixLike__)
#		include <sys/mman.h>
#	elif defined (__Win64__)
#		include <windows.h>
#		include <memoryapi.h>
#	else
#		error 'Unsupported OS'
#	endif

namespace ssc {
	inline void
	lock_os_memory (void const *addr, size_t const length) {
		using namespace std;
#	if    defined (__UnixLike__)
		if (mlock( addr, length ) != 0)
			errx( "Error: Failed to mlock()\n" );
#	elif  defined (__Win64__)
		if (VirtualLock( const_cast<void *>(addr), length ) == 0)
			errx( "Error: Failed to VirtualLock()\n" );
#	else
#		error 'Unsupported OS'
#	endif
	}/* lock_os_memory */

	inline void
	unlock_os_memory (void const *addr, size_t const length) {
		using namespace std;
#	if    defined (__UnixLike__)
		if (munlock( addr, length ) != 0)
			errx( "Error: Failed to munlock()\n" );
#	elif  defined (__Win64__)
		if (VirtualUnlock( const_cast<void *>(addr), length ) == 0)
			errx( "Error: Failed to VirtualUnlock()\n" );
#	else
#		error 'Unsupported OS'
#	endif
	}/* unlock_os_memory */
}/*namespace ssc*/
#endif /*#if defined (ENABLE_MEMORYLOCKING) && !defined (__SSC_DISABLE_MEMORYLOCKING)*/
#undef ENABLE_MEMORYLOCKING
