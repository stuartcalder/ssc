/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstdlib>
#include <cstdio>
#include <shim/macros.h>

namespace ssc {
	struct
	Generic_Error
	{
		static constexpr auto &Alloc_Failure = "Error: Generic Allocation Failure!\n";
	}; // ~ struct Generic_Error
} // ~ namespace ssc
