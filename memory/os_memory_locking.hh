/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <ssc/general/macros.hh>

#ifndef ENABLE_MEMORYLOCKING
/* Memory-lock on all supported operating systems except for OpenBSD.
 */
#	if    (defined (SSC_OS_UNIXLIKE) && !defined (__OpenBSD__)) || defined (SSC_OS_WIN64)
#		define ENABLE_MEMORYLOCKING
#	endif
#else
#	error 'ENABLE_MEMORYLOCKING Already Defined'
#endif

#if    defined (ENABLE_MEMORYLOCKING) && !defined (SSC_FLAG_DISABLE_MEMORYLOCKING)
#	ifndef SSC_FEATURE_MEMORYLOCKING
#		define SSC_FEATURE_MEMORYLOCKING
#	else
#		error 'SSC_FEATURE_MEMORYLOCKING Already defined'
#	endif

#	include <cstdlib>
#	include <ssc/general/integers.hh>
#	include <ssc/general/error_conditions.hh>

/* Get OS-specific headers needed for locking memory.
 */
#	if   defined (SSC_OS_UNIXLIKE)
#		include <sys/mman.h>
#	elif defined (SSC_OS_WIN64)
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
#	if    defined (SSC_OS_UNIXLIKE)
		if( mlock( addr, length ) != 0 )
			errx( "Error: Failed to mlock()\n" );
#	elif  defined (SSC_OS_WIN64)
		if( VirtualLock( const_cast<void *>(addr), length ) == 0 )
			errx( "Error: Failed to VirtualLock()\n" );
#	else
#		error 'Unsupported OS'
#	endif
	}// ~ void lock_os_memory(void*,size_t const)

	inline void
	unlock_os_memory (void const *addr, size_t const length) {
		using namespace std;
#	if    defined (SSC_OS_UNIXLIKE)
		if( munlock( addr, length ) != 0 )
			errx( "Error: Failed to munlock()\n" );
#	elif  defined (SSC_OS_WIN64)
		if( VirtualUnlock( const_cast<void *>(addr), length ) == 0 )
			errx( "Error: Failed to VirtualUnlock()\n" );
#	else
#		error 'Unsupported OS'
#	endif
	}// ~ void unlock_os_memory(void const*, size_t const)
}// ~ namespace ssc
#endif// ~ #if defined (ENABLE_MEMORYLOCKING) && !defined (SSC_FLAG_DISABLE_MEMORYLOCKING)
#undef ENABLE_MEMORYLOCKING
