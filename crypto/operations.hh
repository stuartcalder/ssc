/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <shim/operations.h>
#include <shim/macros.h>

#define SSC_XOR(block,add,bytes) \
	SHIM_MACRO_SHIELD \
		static_assert (bytes == 32 || bytes == 64 || bytes == 128); \
		if        constexpr (bytes == 32) { \
			shim_xor_32( block, add ); \
		} else if constexpr (bytes == 64) { \
			shim_xor_64( block, add ); \
		} else if constexpr (bytes == 128) { \
			shim_xor_128( block, add ); \
		} \
	SHIM_MACRO_SHIELD_EXIT





