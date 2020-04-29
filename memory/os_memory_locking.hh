/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <ssc/general/macros.hh>

#ifndef ENABLE_MEMORYLOCKING
	// Memory-lock on all supported operating systems except for OpenBSD.
#	if    (defined (__UnixLike__) && !defined (__OpenBSD__)) || defined (__Win64__)
#		define ENABLE_MEMORYLOCKING
#	endif
#else
#	error 'ENABLE_MEMORYLOCKING Already Defined'
#endif

// If __SSC_DISABLE_MEMORYLOCKING is defined, do not support memory locking.
#if    defined (ENABLE_MEMORYLOCKING) && !defined (__SSC_DISABLE_MEMORYLOCKING)
// If this macro is defined, consider memory locking to be supported.
#	ifndef __SSC_MemoryLocking__
#		define __SSC_MemoryLocking__
#	else
#		error '__SSC_MemoryLocking__ Already defined'
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

namespace ssc
{
	inline void
	lock_os_memory (void const *addr, size_t const length) {
		using namespace std;
#	if    defined (__UnixLike__)
		if( mlock( addr, length ) != 0 )
			errx( "Error: Failed to mlock()\n" );
#	elif  defined (__Win64__)
		if( VirtualLock( const_cast<void *>(addr), length ) == 0 )
			errx( "Error: Failed to VirtualLock()\n" );
#	else
#		error 'Unsupported OS'
#	endif
	}/* lock_os_memory */

	inline void
	unlock_os_memory (void const *addr, size_t const length) {
		using namespace std;
#	if    defined (__UnixLike__)
		if( munlock( addr, length ) != 0 )
			errx( "Error: Failed to munlock()\n" );
#	elif  defined (__Win64__)
		if( VirtualUnlock( const_cast<void *>(addr), length ) == 0 )
			errx( "Error: Failed to VirtualUnlock()\n" );
#	else
#		error 'Unsupported OS'
#	endif
	}/* unlock_os_memory */
}/*namespace ssc*/
#endif /*#if defined (ENABLE_MEMORYLOCKING) && !defined (__SSC_DISABLE_MEMORYLOCKING)*/
#undef ENABLE_MEMORYLOCKING
