/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <shim/macros.h>
#include <cstdint>
#include <cstddef>

namespace ssc {
	struct SHIM_PUBLIC
	C_Argument_Map
	{

		C_Argument_Map () = delete;

		C_Argument_Map (int const argc, char const *argv[]);

		~C_Argument_Map ();

		static constexpr int Max_Argument_Count = 100;
		char const **c_strings;
		size_t     *sizes;
		size_t     max_string_size;
		int        count;

		bool
		argument_cmp (int const,
			      char const * SHIM_RESTRICT,
			      size_t const);
		bool
		next_string_is_valid (int const);
	};
}// ~ namespace ssc
