/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/files/files.hh>
#include <ssc/files/os_map.hh>

#include <ssc/crypto/implementation/cbc_v2.hh>

namespace ssc {

	// Enums
	enum class Crypto_Method_e {
		None,
#ifdef __SSC_CBC_V2__
		CBC_V2,
#endif
		Terminating_Enum
	};/*enum class Crypto_Method_e*/

	// Compile-Time constants
	inline constexpr size_t DLL_PUBLIC
	Biggest_ID_String_Size (void) {
		size_t s = 0;
#ifdef __SSC_CBC_V2__
		if (sizeof(cbc_v2::CBC_V2_ID) > s)
			s = sizeof(cbc_v2::CBC_V2_ID);
#endif
		return s;
	}/*Biggest_ID_String_Size*/
	inline constexpr size_t DLL_PUBLIC
	Smallest_ID_String_Size (void) {
		size_t s = Biggest_ID_String_Size();
#ifdef __SSC_CBC_V2__
		if (sizeof(cbc_v2::CBC_V2_ID) < s)
			s = sizeof(cbc_v2::CBC_V2_ID);
#endif
		return s;
	}/*Smallest_ID_String_Size*/

	// Functions
	inline Crypto_Method_e DLL_PUBLIC
	determine_crypto_method (char const *filename) {
		auto method = Crypto_Method_e::None;
		// Memory map the file.
		OS_Map os_map;
		os_map.os_file = open_existing_os_file( filename, true );
		os_map.size = get_file_size( os_map.os_file );
		// Check the size of file...
		if (os_map.size < Smallest_ID_String_Size()) {
			close_os_file( os_map.os_file );
			return method;
		}
		map_file( os_map, true );
		// Check if the file is encrypted by a known method...
#ifdef __SSC_CBC_V2__
		{
			using namespace cbc_v2;
			{
				static constexpr auto const Smallest_ID = Smallest_ID_String_Size();
				static constexpr auto const Biggest_ID  = Biggest_ID_String_Size();
				static_assert (sizeof(CBC_V2_ID) >= Smallest_ID);
				static_assert (sizeof(CBC_V2_ID) <= Biggest_ID);
			}
			if ((method == Crypto_Method_e::None) && (memcmp( os_map.ptr, CBC_V2_ID, sizeof(CBC_V2_ID) ) == 0)) {
				method = Crypto_Method_e::CBC_V2;
			}
		}
#else
#	error	"Currently, CBC_V2 is the only supported cryptographic method."
#endif
		// Cleanup.
		unmap_file( os_map );
		close_os_file( os_map.os_file );
		return method;
	}/*determine_crypto_method*/
}/*namespace ssc*/