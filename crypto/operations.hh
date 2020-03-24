/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
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
#include <type_traits>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>

#if    defined (__UnixLike__)
#	include <unistd.h>
#elif  defined (__Win64__)
#	include <windows.h>
#	include <ntstatus.h>
#	include <bcrypt.h>
#else
#	error 'Unsupported OS'
#endif

namespace ssc
{
	static_assert (CHAR_BIT == 8);
	template <typename uint_t>
	uint_t rotate_left (uint_t value, unsigned int count)
	{
		_CTIME_CONST(uint_t) mask = (CHAR_BIT * sizeof(uint_t)) - 1;
		count &= mask;
		return ( value << count ) | ( value >> (-count & mask));
	} /* ~ rotate_left(uint_t,unsigned int) */

	template <typename uint_t>
	uint_t rotate_right (uint_t value, unsigned int count)
	{
		_CTIME_CONST(uint_t) mask = (CHAR_BIT * sizeof(uint_t)) - 1;
		count &= mask;
		return ( value >> count ) | ( value << (-count & mask));
	} /* ~ rotate_right(uint_t,unsigned int) */

	template <int Block_Bits>
	void xor_block (void *__restrict block, void const *__restrict add)
	{
		static_assert (CHAR_BIT == 8);
		static_assert ((Block_Bits % CHAR_BIT == 0), "Bits must be a multiple of bytes");
		_CTIME_CONST(size_t) Block_Bytes = Block_Bits / CHAR_BIT;
		if constexpr(Block_Bits == 128) {
			auto first_dword  = static_cast<u64_t *>(block);
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
			for (int i = 0; i < (Block_Bits / 64); ++i)
				first_dword[ i ] ^= second_dword[ i ];
		} else {
			u8_t *first_byte  = static_cast<u8_t *>(block);
			u8_t const	*second_byte = static_cast<u8_t const *>(add);
			for (int i = 0; i < Block_Bytes; ++i)
				first_byte[ i ] ^= second_byte[ i ];
		}
	}/* ~ xor_block(void*,void*) */

	
	template <typename Integer_t>
	int bit_hamming_weight (Integer_t x)
	{
		// Ensure that Integer_t is a valid, defined type for determining a bit hamming weight.
		_CTIME_CONST(bool) Is_Valid_Type = [](){
			if (std::is_same<Integer_t,u8_t>::value)
				return true;
			else if (std::is_same<Integer_t,u32_t>::value)
				return true;
			else if (std::is_same<Integer_t,u64_t>::value)
				return true;
			else
				return false;
		}();
		static_assert (Is_Valid_Type, "Only u8_t, u32_t, and u64_t allowed as template parameters.");
		// Number_Bytes represents the number of bytes in one Integer_t.
		_CTIME_CONST(int)  Number_Bytes = sizeof(Integer_t);
		static_assert (Number_Bytes >= 1);
		static_assert (CHAR_BIT == 8);
		// Number_Bits represents the number of bits to check for 1's to determine the bit hamming weight.
		_CTIME_CONST(int)  Number_Bits = Number_Bytes * CHAR_BIT;

		int hamming_weight = 0;

		static_assert (Number_Bytes == 1 || Number_Bytes == 4 || Number_Bytes == 8);
		if constexpr(Number_Bytes == 1) {
			static_assert (sizeof(u8_t) == 1);
			u8_t byte_mask = 0b1000'0000;
			for (int i = 0; i < Number_Bits; ++i) {
				if (x & byte_mask)
					++hamming_weight;
				byte_mask >>= 1;
			}
		} else if constexpr(Number_Bytes == 4) {
			static_assert (sizeof(u32_t) == 4);
			u32_t mask = 0b10000000'00000000'00000000'00000000;
			for (int i = 0; i < Number_Bits; ++i) {
				if (x & mask)
					++hamming_weight;
				mask >>= 1;
			}
		} else if constexpr(Number_Bytes == 8) {
			static_assert (sizeof(u64_t) == 8);
			u64_t mask = 0b10000000'00000000'00000000'00000000'00000000'00000000'00000000'00000000;
			for (int i = 0; i < Number_Bits; ++i) {
				if (x & mask)
					++hamming_weight;
				mask >>= 1;
			}
		}
		return hamming_weight;
	}/* ~ bit_hamming_weight(Integer_t) */

	inline void obtain_os_entropy (u8_t *buffer, size_t num_bytes)
	{
                using namespace std;
#if    defined (__UnixLike__)
		_CTIME_CONST(int) Max_Bytes = 256;
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
#	error 'Unsupported OS'
#endif
	} /* ~ obtain_os_entropy(u8_t *,size_t) */

	inline void zero_sensitive (void *buffer, size_t num_bytes)
	{
		using namespace std;
#if    defined (__UnixLike__)
		explicit_bzero( buffer, num_bytes );
#elif  defined (__Win64__)
		SecureZeroMemory( buffer, num_bytes );
#else
#	error 'Unsupported OS'
#endif
	} /* ~ zero_sensitive(u8_t *,size_t) */
	
}/* ~ namespace ssc */
