/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/

/* operations.hh
 * No operating-system specific code here
 */
#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
/* C Standard Headers */
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
/* C++ Standard Headers */
#include <type_traits>
/* OS-Specific Headers */
#if    defined (__UnixLike__)
#	include <unistd.h>
#elif  defined (__Win64__)
#	include <windows.h>
#	include <ntstatus.h>
#	include <bcrypt.h>
#else
#	error 'Unsupported OS'
#endif
/* Byte-swapping OS-Specific Headers */
#if    defined (__OpenBSD__)
#	include <endian.h>
#elif  defined (__FreeBSD__)
#	include <sys/endian.h>
#elif  defined (__gnu_linux__)
#	include <byteswap.h>
#elif  defined (__Win64__)
#	include <stdlib.h>
#else
#	error 'Unsupported OS'
#endif

#if    defined (STATIC_ENFORCE_UNSIGNED_INTEGRAL)
#	error 'STATIC_ENFORCE_UNSIGNED_INTEGRAL Already Defined'
#else
#	define STATIC_ENFORCE_UNSIGNED_INTEGRAL(Type) \
		static_assert ( \
			(std::is_same<Type,u8_t>::value || \
			 std::is_same<Type,u16_t>::value || \
			 std::is_same<Type,u32_t>::value || \
			 std::is_same<Type,u64_t>::value), \
			"Only unsigned integral types allowed for this type." \
		)
#endif

namespace ssc
{
	static_assert (CHAR_BIT == 8);
	template <typename Uint_t>
	Uint_t rotate_left (Uint_t value, unsigned int count)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL( Uint_t );

		_CTIME_CONST(Uint_t) mask = (CHAR_BIT * sizeof(Uint_t)) - 1;
		count &= mask;
		return ( value << count ) | ( value >> (-count & mask));
	} /* ~ Uint_t rotate_left(Uint_t,unsigned int) */

	template <typename Uint_t>
	Uint_t rotate_right (Uint_t value, unsigned int count)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL( Uint_t );

		_CTIME_CONST(Uint_t) mask = (CHAR_BIT * sizeof(Uint_t)) - 1;
		count &= mask;
		return ( value >> count ) | ( value << (-count & mask));
	} /* ~ Uint_t rotate_right(Uint_t,unsigned int) */

	template <int Block_Bits>
	void xor_block (void *__restrict block, void const *__restrict add)
	{
		static_assert (CHAR_BIT == 8);
		static_assert ((Block_Bits % CHAR_BIT == 0), "Bits must be a multiple of bytes");
		_CTIME_CONST(int) Block_Bytes = Block_Bits / CHAR_BIT;
		if constexpr(Block_Bits == 128) {
			u64_t       *first_dword  = static_cast<u64_t *>(block);
			u64_t const *second_dword = static_cast<u64_t const *>(add);
			static_assert (Block_Bits / 64 == 2);
			first_dword[ 0 ] ^= second_dword[ 0 ];
			first_dword[ 1 ] ^= second_dword[ 1 ];
		} else if constexpr(Block_Bits == 256) {
			u64_t       *first_dword  = static_cast<u64_t *>(block);
			u64_t const *second_dword = static_cast<u64_t const *>(add);

			static_assert (Block_Bits / 64 == 4);
			first_dword[ 0 ] ^= second_dword[ 0 ];
			first_dword[ 1 ] ^= second_dword[ 1 ];
			first_dword[ 2 ] ^= second_dword[ 2 ];
			first_dword[ 3 ] ^= second_dword[ 3 ];
		} else if constexpr(Block_Bits == 512) {
			u64_t       *first_dword  = static_cast<u64_t *>(block);
			u64_t const *second_dword = static_cast<u64_t const *>(add);

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
			_CTIME_CONST(int) Number_Words = Block_Bits / 64;
			u64_t       *first_dword  = static_cast<u64_t *>(block);
			u64_t const *second_dword = static_cast<u64_t const *>(add);
			for (int i = 0; i < Number_Words; ++i)
				first_dword[ i ] ^= second_dword[ i ];
		} else {
			u8_t            *first_byte  = static_cast<u8_t *>(block);
			u8_t const	*second_byte = static_cast<u8_t const *>(add);
			for (int i = 0; i < Block_Bytes; ++i)
				first_byte[ i ] ^= second_byte[ i ];
		}
	}/* ~ xor_block(void*,void*) */

	
	template <typename Uint_t>
	int bit_hamming_weight (Uint_t x)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL( Uint_t );

		// Number_Bytes represents the number of bytes in one Uint_t.
		_CTIME_CONST(int)  Number_Bytes = sizeof(Uint_t);
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
	}/* ~ bit_hamming_weight(Uint_t) */

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

	template <typename Uint_t>
	Uint_t reverse_byte_order (Uint_t u)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL( Uint_t );

		// Disallow Uint_t to be u8_t, since it cannot be reversed.
		static_assert (!std::is_same<Uint_t,u8_t>::value, "u8_t is not byte reversible.");

#if    defined (SWAP_F)
#	error 'SWAP_F Already Defined'
#else
#	define SWAP_F(size,u)	SWAP_F__( size, u )
#endif

#if    defined (SWAP_F__)
#	error 'SWAP_F__ Already Defined'
#elif  defined (__OpenBSD__)
#	define SWAP_F__(size,u)	swap##size( u )
#elif  defined (__FreeBSD__)
#	define SWAP_F__(size,u)	bswap##size( u )
#elif  defined (__gnu_linux__)
#	define SWAP_F__(size,u)	bswap_##size( u )
#elif  defined (__Win64__)
#	define SWAP_F__(size,u)	_byteswap_##size( u );
#else
#	error 'Unsupported OS'
#endif

#if    defined (SIZE)
#	error 'SIZE Already Defined'
#elif  defined (__UnixLike__)
#	define SIZE(unixlike,win64) unixlike
#elif  defined (__Win64__)
#	define SIZE(unixlike,win64) win64
#else
#	error 'Unsupported OS'
#endif
		if constexpr(std::is_same<Uint_t,u16_t>::value) {
			return SWAP_F( SIZE( 16, ushort ), u );
		} else if constexpr(std::is_same<Uint_t,u32_t>::value) {
			return SWAP_F( SIZE( 32, ulong ), u );
		} else if constexpr(std::is_same<Uint_t,u64_t>::value) {
			return SWAP_F( SIZE( 64, uint64 ), u );
		}
#undef SIZE
#undef SWAP_F__
#undef SWAP_F
	}/* ~ Uint_t reverse_byte_order (Uint_t) */
	
}/* ~ namespace ssc */
#undef STATIC_ENFORCE_UNSIGNED_INTEGRAL
