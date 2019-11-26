/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/* operations.hh
 * No operating-system specific code here
 */
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/error_conditions.hh>

#if    defined (__UnixLike__)
#	include <unistd.h>
#elif  defined (__Win64__)
#	include <windows.h>
#	include <ntstatus.h>
#	include <bcrypt.h>
#else
#	error "Operations.hh only implemented for OpenBSD, GNU/Linux, and 64-bit Microsoft Windows"
#endif

namespace ssc {
	static_assert (CHAR_BIT == 8);
	template <typename uint_t>
	uint_t
	rotate_left (uint_t value, unsigned int count) {
		uint_t const mask = (CHAR_BIT * sizeof(uint_t)) - 1;
		count &= mask;
		return ( value << count ) | ( value >> (-count & mask));
	}

	template <typename uint_t>
	uint_t
	rotate_right (uint_t value, unsigned int count) {
		uint_t const mask = (CHAR_BIT * sizeof(uint_t)) - 1;
		count &= mask;
		return ( value >> count ) | ( value << (-count & mask));
	}

	template <size_t Block_Bits>
	void
	xor_block (void *__restrict block, void const *__restrict add) {
		static_assert (CHAR_BIT == 8);
		static_assert ((Block_Bits % CHAR_BIT == 0), "Bits must be a multiple of bytes");
		static constexpr size_t const Block_Bytes = Block_Bits / 8;
		if constexpr(Block_Bits == 128) {
			auto first_dword =  static_cast<u64_t *>(block);
			auto second_dword = static_cast<u64_t const *>(add);
			static_assert (Block_Bits / 64 == 2);
			first_dword[ 0 ] ^= second_dword[ 0 ];
			first_dword[ 1 ] ^= second_dword[ 1 ];
		} else if constexpr(Block_Bits == 256) {
			auto first_dword =  static_cast<u64_t *>(block);
			auto second_dword = static_cast<u64_t const *>(add);

			static_assert (Block_Bits / 64 == 4);
			first_dword[ 0 ] ^= second_dword[ 0 ];
			first_dword[ 1 ] ^= second_dword[ 1 ];
			first_dword[ 2 ] ^= second_dword[ 2 ];
			first_dword[ 3 ] ^= second_dword[ 3 ];
		} else if constexpr(Block_Bits == 512) {
			auto first_dword  = static_cast<u64_t *>(block);
			auto second_dword = static_cast<u64_t const *>(add);

			static_assert (Block_Bits / 64 == 8);
			first_dword[ 0 ] ^= second_dword[ 0 ];
			first_dword[ 1 ] ^= second_dword[ 1 ];
			first_dword[ 2 ] ^= second_dword[ 2 ];
			first_dword[ 3 ] ^= second_dword[ 3 ];
			first_dword[ 4 ] ^= second_dword[ 4 ];
			first_dword[ 5 ] ^= second_dword[ 5 ];
			first_dword[ 6 ] ^= second_dword[ 6 ];
			first_dword[ 7 ] ^= second_dword[ 7 ];
		} else if constexpr((Block_Bits > 512) && (Block_Bits % 64 == 0)) {
			auto first_dword  = static_cast<u64_t *>(block);
			auto second_dword = static_cast<u64_t const *>(add);
			for (size_t i = 0; i < (Block_Bits / 64); ++i)
				first_dword[ i ] ^= second_dword[ i ];
		} else {
			byte_t		*first_byte  = static_cast<byte_t *>(block);
			byte_t const	*second_byte = static_cast<byte_t const *>(add);
			for (size_t i = 0; i < Block_Bytes; ++i)
				first_byte[ i ] ^= second_byte[ i ];
		}
	}/* ! xor_block */
	
	inline void
	obtain_os_entropy (byte_t *buffer, size_t num_bytes) {
                using namespace std;
#if    defined (__UnixLike__)
                static constexpr size_t const Max_Bytes = 256;
                while (num_bytes >= Max_Bytes) {
                        if (getentropy( buffer, Max_Bytes ) != 0)
				errx( "Error: Failed to getentropy()\n" );
			num_bytes -= Max_Bytes;
			buffer    += Max_Bytes;
		}
		if (getentropy( buffer, num_bytes ) != 0)
			errx( "Error: Failed to getentropy()\n" );
#elif  defined (__Win64__)
		BCRYPT_ALG_HANDLE cng_provider_handle;
		// Open algorithm provider.
		if (BCryptOpenAlgorithmProvider( &cng_provider_handle, L"RNG", nullptr, 0 ) != STATUS_SUCCESS)
			errx( "Error: BCryptOpenAlgorithmProvider() failed\n" );
		// Generate randomness.
		if (BCryptGenRandom( cng_provider_handle, buffer, num_bytes, 0 ) != STATUS_SUCCESS)
			errx( "Error: BCryptGenRandom() failed\n" );
		// Close algorithm provider.
		if (BCryptCloseAlgorithmProvider( cng_provider_handle, 0 ) != STATUS_SUCCESS)
			errx( "Error: BCryptCloseAlgorithmProvider() failed\n" );
#else
#	error "ssc::obtain_os_entropy defined for OpenBSD, GNU/Linux, and MS Windows"
#endif
	} /* obtain_os_entropy (byte_t *,size_t) */

	inline void
	zero_sensitive (void *buffer, size_t num_bytes) {
		using namespace std;
#if    defined (__UnixLike__)
		explicit_bzero( buffer, num_bytes );
#elif  defined (__Win64__)
		SecureZeroMemory( buffer, num_bytes );
#else
#	error "ssc::zero_sensitive defined for OpenBSD, GNU/Linux, and MS Windows"
#endif
	} /* ! zero_sensitive (byte_t *,size_t) */
	
}/* ! namespace ssc */
