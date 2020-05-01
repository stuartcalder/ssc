/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <ssc/general/macros.hh>

namespace ssc
{
	struct _PUBLIC C_Argument_Map
	{
		_CTIME_CONST (int) Max_Argument_Count = 100;
		C_Argument_Map () = delete;
		C_Argument_Map (int const argc, char const *argv[]);
		~C_Argument_Map ();
		char const **c_strings;
		size_t     *sizes;
		size_t     max_string_size;
		int        count;
	};
}/* namespace ssc */
