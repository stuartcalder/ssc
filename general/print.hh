/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstdint>
#include <cstdio>
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>

namespace ssc {
	void SSC_PUBLIC
	print_binary_buffer (const uint8_t * buffer, const size_t num_bytes);
    
	template <typename Uint_t> void
	print_integral_buffer (Uint_t * const i_buf, const size_t num_elements)
	{
		static constexpr auto const &format_str = [](size_t const size) {
			if (size == sizeof(unsigned char))
				return "%02hhx";
			else if (size == sizeof(unsigned short))
				return "%2hx";
			else if (size == sizeof(unsigned int))
				return "%x";
			else if (size == sizeof(unsigned long))
				return "%8lx";
			else if (size == sizeof(unsigned long long))
				return "%8llx";
			else if (size == sizeof(size_t))
				return "%zx";
			else
				return "";
		}( sizeof(Uint_t) );
		using std::printf, std::fputs, std::putchar;

		if (num_elements == 0)
			return;
		Uint_t const *alias = reinterpret_cast<Uint_t const *>(i_buf);

		auto const backtick_one_index = num_elements - 1;

		for( size_t i = 0; i < backtick_one_index; ++i ) {
			printf( format_str, alias[ i ] );
		}
		printf( format_str, alias[ backtick_one_index ] );
	}// ~ void print_integral_buffer (Uint_t * const, size_t const)
}// ~ namespace ssc
