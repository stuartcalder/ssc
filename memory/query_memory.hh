/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <ssc/general/macros.hh>
#if    defined (__UnixLike__) && !defined (__Mac_OSX__)
#	ifdef __SSC_QueryMemory__
#		error 'Somehow __SSC_QueryMemory__ is already defined!'
#	endif
#	define __SSC_QueryMemory__
#	include <ssc/general/integers.hh>
#	include <unistd.h>
#	include <limits>
namespace ssc
{
	_CTIME_CONST (u64_t) Query_Free_Fail = (std::numeric_limits<u64_t>::max)();

	[[nodiscard]]
	inline u64_t query_free_memory ()
	{
		auto const page_size = sysconf( _SC_PAGESIZE );
		if( page_size == -1 )
			return Query_Free_Fail;
		auto const number_avail_pages = sysconf( _SC_AVPHYS_PAGES );
		if( number_avail_pages == -1 )
			return Query_Free_Fail;
		return static_cast<u64_t>(page_size) * static_cast<u64_t>(number_avail_pages);
	}
}/* ~ namespace ssc */
#endif
