/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <shim/operations.h>

namespace ssc {
	struct
	Bit_Reversal_Graph_F
	{
	/* index (u64_t,u8_t const) -> u64_t
	 * 	Bit reversal graph generic indexing function for Catena.
	 */
		static inline uint64_t
		index (uint64_t i, uint8_t const garlic) {
			i = shim_swap_64( i );
			i = ((i & static_cast<uint64_t>(0x0f'0f'0f'0f'0f'0f'0f'0f)) << 4) |
			    ((i & static_cast<uint64_t>(0xf0'f0'f0'f0'f0'f0'f0'f0)) >> 4);
			i = ((i & static_cast<uint64_t>(0x33'33'33'33'33'33'33'33)) << 2) |
			    ((i & static_cast<uint64_t>(0xcc'cc'cc'cc'cc'cc'cc'cc)) >> 2);
			i = ((i & static_cast<uint64_t>(0x55'55'55'55'55'55'55'55)) << 1) |
			    ((i & static_cast<uint64_t>(0xaa'aa'aa'aa'aa'aa'aa'aa)) >> 1);
			return i >> (64 - garlic);
		}
	};
}// ~ namespace ssc
