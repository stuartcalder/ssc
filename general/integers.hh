/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include <climits>

namespace ssc {
	inline namespace ints {
		// Unsigned integer types
		using u8_t  = std::uint8_t;
		static_assert (CHAR_BIT == 8);
		using u16_t = std::uint16_t;
		using u32_t = std::uint32_t;
		using u64_t = std::uint64_t;
		using	      std::size_t;
		// Signed types
		using i8_t  = std::int8_t;
		using i16_t = std::int16_t;
		using i32_t = std::int32_t;
		using i64_t = std::int64_t;
	}/*namespace ssc::ints*/
}/*namespace ssc*/
