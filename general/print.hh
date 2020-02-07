/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once
#include <cstdint>
#include <cstdio>
#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>

namespace ssc {
	void DLL_PUBLIC
	print_binary_buffer (const uint8_t * buffer, const size_t num_bytes);
    
	template <typename Uint_t>
	void
	print_integral_buffer (Uint_t * const i_buf, const size_t num_elements) {
		_CTIME_CONST(auto &) format_str = [](size_t const size) {
			if (size == sizeof(unsigned char))
				return "%2hhx";
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
        auto alias = reinterpret_cast<Uint_t const *>(i_buf);
        
        printf( "0x" );
        auto const backtick_one_index = num_elements - 1;

        for ( size_t i = 0; i < backtick_one_index; ++i ) {
	    printf( format_str, alias[ i ] );
            fputs( ","/*TODO*/, stdout );
        }
        printf( format_str, alias[ backtick_one_index ] );
        putchar( '\n' );
    }
}/* ! namespace isc */
