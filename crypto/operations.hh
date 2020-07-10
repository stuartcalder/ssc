/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
/* SSC General
 */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
/* C Std
 */
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
/* C++ Std
 */
#include <type_traits>
/* OS-Specific
 */
#if    defined (SSC_OS_UNIXLIKE)
#	include <unistd.h>
	/* for byte-swapping */
#	if    defined (__OpenBSD__)
#		include <endian.h>
#	elif  defined (__FreeBSD__)
#		include <sys/endian.h>
#	elif  defined (__NetBSD__)
#		include <sys/types.h>
#		include <machine/bswap.h>
#		include <string.h>
#		include <sys/param.h>
#	elif  defined (__gnu_linux__)
#		include <byteswap.h>
	/* for reading from /dev/random, access to memset_s */
#	elif  defined (SSC_OS_OSX)
#		if   !defined (__STDC_WANT_LIB_EXT1__) || (__STDC_WANT_LIB_EXT1__ != 1)
#			error 'The macro __STDC_WANT_LIB_EXT1__ must be #defined to 1 for access to memset_s.'
#		endif
#		include <ssc/files/files.hh>
#		include <string.h>
#	else
#		error 'Unsupported Unix-like operating system?'
#	endif
#elif  defined (SSC_OS_WIN64)
#	include <windows.h>
#	include <ntstatus.h>
#	include <bcrypt.h>
#	include <stdlib.h> /* for byte-swapping */
#else
#	error 'Unsupported OS'
#endif// ~ #if defined (SSC_OS_UNIXLIKE)

/* Ensure that the template functions below that expect unsigned integral
 * types can ONLY be used with unsigned integral types, to prevent any
 * unexpectedly nasty behavior.
 */
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
#endif// ~ #if defined (STATIC_ENFORCE_UNSIGNED_INTEGRAL)

namespace ssc {
/* rotate_left (Uint_t) -> Uint_t
 * 	Bitwise rotation left of an unsigned integer of type `Uint_t` by a constant, $Count.
 */
	template <unsigned int Count, typename Uint_t> [[nodiscard]] constexpr Uint_t
	rotate_left (Uint_t value)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL (Uint_t);

		constexpr Uint_t Mask = (CHAR_BIT * sizeof(Uint_t)) - 1;
		constexpr Uint_t Masked_Count = Mask & Count;
		return (value << Masked_Count) | (value >> (-Masked_Count & Mask));
	}


/* rotate_right (Uint_t) -> Uint_t
 * 	Bitwise rotation right of an unsigned integer of type `Uint_t` by a constant, $Count.
 */
	template <unsigned int Count, typename Uint_t> [[nodiscard]] constexpr Uint_t
	rotate_right (Uint_t value)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL (Uint_t);

		constexpr Uint_t Mask = (CHAR_BIT * sizeof(Uint_t)) - 1;
		constexpr Uint_t Masked_Count = Mask & Count;
		return (value >> Masked_Count) | (value << (-Masked_Count & Mask));
	}


/* xor_block (SSC_RESTRICT(void*),SSC_RESTRICT(void const*)) -> void
 * 	XOR two blocks of data, $block and $add, both $Block_Bits large, storing the result pointed to by $block.
 */
	template <int Block_Bits> void
	xor_block (SSC_RESTRICT (void *)       block,
		   SSC_RESTRICT (void const *) add)
	{
		static_assert (CHAR_BIT == 8,
			       "One byte must be 8 bits.");
		static_assert ((Block_Bits % CHAR_BIT == 0),
			       "Bits must be a multiple of bytes");
		static constexpr int Block_Bytes = Block_Bits / CHAR_BIT;
		for( int i = 0; i < Block_Bytes; ++i )
			reinterpret_cast<u8_t*>(block)[ i ] ^= reinterpret_cast<u8_t const*>(add)[ i ];
	}// ~ xor_block(SSC_RESTRICT(void*),SSC_RESTRICT(void const*))

	
/* bit_hamming_weight (Uint_t) -> int
 * 	TODO
 */
	template <typename Uint_t> int
	bit_hamming_weight (Uint_t x)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL(Uint_t);

	// $Number_Bytes represents the number of bytes in one Uint_t.
		static constexpr int Number_Bytes = sizeof(Uint_t);
		static_assert (CHAR_BIT == 8);
	// $Number_Bits represents the number of bits to check for 1's to determine the bit hamming weight.
		static constexpr int Number_Bits = Number_Bytes * CHAR_BIT;

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
	}// ~ bit_hamming_weight (Uint_t)


/* obtain_os_entropy (u8_t*,size_t) -> void
 * 	Obtain $num_bytes pseudorandom bytes from the operating-system, storing them at the
 * 	byte address pointed to by $buffer.
 */
	inline void
	obtain_os_entropy (u8_t *buffer, size_t num_bytes)
	{
                using namespace std;
	/* It appears that reading from /dev/random is consistent on OSX, but blocks often on NetBSD.
	 * Read from /dev/urandom by default on NetBSD and /dev/random on OSX.
	 */
#if    defined (SSC_OS_OSX) || (defined (__NetBSD__) && (__NetBSD_Version__ < 1000000000))
#	if    defined (SSC_OS_OSX)
#		define RANDOM_DEVICE "/dev/random"
#	elif  defined (__NetBSD__)
#		define RANDOM_DEVICE "/dev/urandom"
#	else
#		error 'This should be impossibe.'
#	endif
		OS_File_t random_dev = open_existing_os_file( RANDOM_DEVICE, true );
		if( read( random_dev, buffer, num_bytes ) != static_cast<ssize_t>(num_bytes) )
			errx( "Error: Failed to read from " RANDOM_DEVICE "\n" );
		close_os_file( random_dev );
#	undef RANDOM_DEVICE
	/* For OpenBSD, FreeBSD, GNU/Linux, and NetBSD >= 10.0, we can use getentropy() to obtain OS entropy.
	 */
#elif  defined (SSC_OS_UNIXLIKE)
		static constexpr size_t Max_Bytes = 256;
                while( num_bytes > Max_Bytes ) {
                        if( getentropy( buffer, Max_Bytes ) != 0 )
				errx( "Error: Failed to getentropy()\n" );
			num_bytes -= Max_Bytes;
			buffer    += Max_Bytes;
		}
		if( getentropy( buffer, num_bytes ) != 0 )
			errx( "Error: Failed to getentropy()\n" );
	/* For Win64, use the newer crypto functions from bcrypt.dll
	 */
#elif  defined (SSC_OS_WIN64)
		BCRYPT_ALG_HANDLE cng_provider_handle;
		// Open algorithm provider.
		if( BCryptOpenAlgorithmProvider( &cng_provider_handle, L"RNG", nullptr, 0 ) != STATUS_SUCCESS )
			errx( "Error: BCryptOpenAlgorithmProvider() failed\n" );
		// Generate randomness.
		if( BCryptGenRandom( cng_provider_handle, buffer, num_bytes, 0 ) != STATUS_SUCCESS )
			errx( "Error: BCryptGenRandom() failed\n" );
		// Close algorithm provider.
		if( BCryptCloseAlgorithmProvider( cng_provider_handle, 0 ) != STATUS_SUCCESS )
			errx( "Error: BCryptCloseAlgorithmProvider() failed\n" );
#else
#	error 'Unsupported OS'
#endif
	} // ~ obtain_os_entropy(u8_t*,size_t)


/* zero_sensitive (void*,size_t) -> void
 * 	Write $num_bytes null bytes to the buffer pointed to by $buffer.
 * 	Prevent the compiler from optimizing away this call.
 */
	inline void
	zero_sensitive (void *buffer, size_t num_bytes)
	{
		using namespace std;
	/* It seems OSX doesn't support explicit_bzero, but it does support memset_s.
	 * Use memset_s since it's there.
	 */
#if    defined (SSC_OS_OSX)
		static_cast<void>(memset_s( buffer, num_bytes, 0, num_bytes ));
	/* NetBSD doesn't seem to support explicit_bzero, but provides its own function
	 * for destroying buffers.
	 */
#elif  defined (__NetBSD__)
		static_cast<void>(explicit_memset( buffer, 0, num_bytes ));
	/* It appears OpenBSD, FreeBSD, and GNU/Linux all support the explicit_bzero call.
	 */
#elif  defined (SSC_OS_UNIXLIKE)
		explicit_bzero( buffer, num_bytes );
	/* SecureZeroMemory is the only function I could find on Win64 that fulfills this purpose.
	 */
#elif  defined (SSC_OS_WIN64)
		SecureZeroMemory( buffer, num_bytes );
#else
#	error 'Unsupported OS'
#endif
	} // ~ zero_sensitive(u8_t*,size_t)


/* reverse_byte_order (Uint_t) -> (Uint_t)
 * 	Reverse the byte order of the unsigned integer $u, of type `Uint_t`.
 * 	i.e. little-endian -> big-endian, or big-endian -> little-endian.
 */
	template <typename Uint_t> [[nodiscard]] Uint_t
	reverse_byte_order (Uint_t u)
	{
		STATIC_ENFORCE_UNSIGNED_INTEGRAL (Uint_t);

		// Disallow Uint_t to be u8_t, since it cannot be reversed.
		static_assert (!std::is_same<Uint_t,u8_t>::value, "u8_t is not byte reversible.");

#if    defined (SWAP_F) || defined (SWAP_F_IMPL) || defined (SIZE)
#	error 'SWAP_F, SWAP_F_IMPL, or SIZE macro already defined'
#endif

#define SWAP_F(size,u)	SWAP_F_IMPL (size,u)

#if    defined (__OpenBSD__)
#	define SWAP_F_IMPL(size,u)	swap##size( u )
#elif  defined (__FreeBSD__) || defined (__NetBSD__)
#	define SWAP_F_IMPL(size,u)	bswap##size( u )
#elif  defined (__gnu_linux__)
#	define SWAP_F_IMPL(size,u)	bswap_##size( u )
#elif  defined (SSC_OS_WIN64)
#	define SWAP_F_IMPL(size,u)	_byteswap_##size( u )
#elif !defined (SSC_OS_OSX)
#	error 'Unsupported OS'
#endif

#if    defined (SSC_OS_UNIXLIKE) && !defined (SSC_OS_OSX)
#	define SIZE(unixlike,win64) unixlike
#elif  defined (SSC_OS_WIN64)
#	define SIZE(unixlike,win64) win64
#elif !defined (SSC_OS_OSX)
#	error 'Unsupported OS'
#endif

#ifdef SSC_OS_OSX
	/* It seems there are no native calls for swapping byte order on OSX;
	 * implement it ourselves.
	 */
		if constexpr (std::is_same<Uint_t,u16_t>::value) {
			//     [00ff]     [ff00]
			return (u >> 8) | (u << 8);
		} else if constexpr (std::is_same<Uint_t,u32_t>::value) {
			// 0 1 2 3
			// 3 2 1 0
			return (u >> (3*8)) |
			       ((u >> 8) & 0x00'00'ff'00) |
			       ((u << 8) & 0x00'ff'00'00) |
			       (u << (3*8));
		} else if constexpr (std::is_same<Uint_t,u64_t>::value) {
			// 0 1 2 3 4 5 6 7
			// 7 6 5 4 3 2 1 0
			return (u >> (7*8))    /* spacing */              |
			       ((u >> (5*8)) & 0x00'00'00'00'00'00'ff'00) |
			       ((u >> (3*8)) & 0x00'00'00'00'00'ff'00'00) |
			       ((u >> 8    ) & 0x00'00'00'00'ff'00'00'00) |
			       ((u << 8    ) & 0x00'00'00'ff'00'00'00'00) |
			       ((u << (3*8)) & 0x00'00'ff'00'00'00'00'00) |
			       ((u << (5*8)) & 0x00'ff'00'00'00'00'00'00) |
			       (u << (7*8));
		}
#else
/* All supported platforms except OSX provide specific functions to call for byte-swapping.
 * Call those functions here.
 */
		if constexpr (std::is_same<Uint_t,u16_t>::value) {
			return SWAP_F (SIZE (16,ushort),u);
		} else if constexpr (std::is_same<Uint_t,u32_t>::value) {
			return SWAP_F (SIZE (32,ulong),u);
		} else if constexpr (std::is_same<Uint_t,u64_t>::value) {
			return SWAP_F (SIZE (64,uint64),u);
		}
#endif// ~ #ifdef SSC_OS_OSX
#undef SIZE
#undef SWAP_F_IMPL
#undef SWAP_F
	}// ~ Uint_t reverse_byte_order (Uint_t)


/* constant_time_memcmp (SSC_RESTRICT(void const*),SSC_RESTRICT(void const*),size_t const) -> int
 * 	Return the number of different bytes between the two buffers $left and $right.
 * 	Take the same amount of time, no matter how many of those bytes are or are not different.
 */
	[[nodiscard]] inline int
	constant_time_memcmp (SSC_RESTRICT (void const*) left,
			      SSC_RESTRICT (void const*) right,
			      size_t const               size)
	{
		int non_equal_bytes = 0;
		static constexpr u8_t One_Mask = 0b0000'0001;
		for( size_t i = 0; i < size; ++i ) {
			u8_t const b = reinterpret_cast<u8_t const*>( left)[ i ] ^
				       reinterpret_cast<u8_t const*>(right)[ i ];
			non_equal_bytes += (((b >> 7)           ) |
					    ((b >> 6) & One_Mask) |
					    ((b >> 5) & One_Mask) |
					    ((b >> 4) & One_Mask) |
					    ((b >> 3) & One_Mask) |
					    ((b >> 2) & One_Mask) |
					    ((b >> 1) & One_Mask) |
					    ((b     ) & One_Mask));
		}
		return non_equal_bytes;
	}
	
}// ~ namespace ssc
#undef STATIC_ENFORCE_UNSIGNED_INTEGRAL
