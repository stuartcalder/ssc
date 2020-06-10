/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <ssc/general/macros.hh>
#if    defined (SSC_OS_UNIXLIKE) && !defined (SSC_OS_OSX)
#	ifdef SSC_FEATURE_QUERYMEMORY
#		error 'SSC_FEATURE_QUERYMEMORY already defined!'
#	endif
#	define SSC_FEATURE_QUERYMEMORY
#	include <ssc/general/integers.hh>
#	include <unistd.h>
#	include <limits>
namespace ssc {
	static constexpr u64_t Query_Free_Fail = (std::numeric_limits<u64_t>::max)();

	[[nodiscard]] inline u64_t
	query_free_memory ()
	{
		auto const page_size = sysconf( _SC_PAGESIZE );
		if( page_size == -1 )
			return Query_Free_Fail;
		auto const number_avail_pages = sysconf( _SC_AVPHYS_PAGES );
		if( number_avail_pages == -1 )
			return Query_Free_Fail;
		return static_cast<u64_t>(page_size) * static_cast<u64_t>(number_avail_pages);
	}
} // ~ namespace ssc
#endif
