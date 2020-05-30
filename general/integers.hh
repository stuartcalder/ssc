/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <climits>

namespace ssc {
	inline namespace ints {
	/* Unsigned integer types.
	 */
		static_assert (CHAR_BIT == 8,
			       "SSC required 8-bit bytes.");
		using u8_t  = std::uint8_t;
		using u16_t = std::uint16_t;
		using u32_t = std::uint32_t;
		using u64_t = std::uint64_t;
		using	      std::size_t;
	/* Signed integer types.
	 */
		using i8_t  = std::int8_t;
		using i16_t = std::int16_t;
		using i32_t = std::int32_t;
		using i64_t = std::int64_t;
	}// ~ inline namespace ints
	static_assert (sizeof(u64_t) == 8, "Later code assumes 64-bit ints to be 8 bytes.");
	static_assert (sizeof(u32_t) == 4, "Later code assumes 32-bit ints to be 4 bytes.");
	static_assert (sizeof(u16_t) == 2, "Later code assumes 16-bit ints to be 2 bytes.");
	static_assert (sizeof(u8_t)  == 1, "Later code assumes 8-bit ints to be 1 byte.");
}// ~ namespace ssc
