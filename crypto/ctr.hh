/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>

#include <utility>
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/crypto/operations.hh>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS template <typename Block_Cipher_t, int Block_Bits>
#else
#	error 'TEMPLATE_ARGS Already defined'
#endif

#ifndef CLASS
#	define CLASS CTR_Mode<Block_Cipher_t,Block_Bits>
#else
#	error 'CLASS Already defined'
#endif

namespace ssc
{
	TEMPLATE_ARGS
	class CTR_Mode
	{
	public:
	/* Compile-Time Constants and checks*/
		static_assert (CHAR_BIT == 8);
		static_assert (Block_Bits % CHAR_BIT == 0);
		static_assert (Block_Bits >= 128, "Modern block ciphers have blocks of at least 128 bits.");
		static_assert (Block_Cipher_t::Block_Bits == Block_Bits);
		_CTIME_CONST(int) Block_Bytes = Block_Bits / CHAR_BIT;
		static_assert (Block_Bytes % 2 == 0, "We must be able to divide the bytes of one block evenly in half.");
		_CTIME_CONST(int) Nonce_Bytes = Block_Bytes / 2;
		_CTIME_CONST(int) Buffer_Bytes = Nonce_Bytes + (Block_Bytes * 2);

	/* Constructors */
		CTR_Mode (void) = delete;

		CTR_Mode (Block_Cipher_t*, u8_t*);

		template <typename... Args>
		CTR_Mode (Block_Cipher_t *b_cipher, u8_t *ctr_data, Args... args);

	/* Public Procedures */
		inline void set_nonce (u8_t const *nonce);

		void xorcrypt (u8_t *output, u8_t const *input, u64_t const input_size, u64_t start = 0);
	private:
	/* Private Data */
		Block_Cipher_t	*blk_cipher;
		/* u8_t pointer 'data' layout
		 * 
		 * offset 0
		 * |
		 * V
		 * [Nonce......][Keystream_Plaintext][Temp_Buffer] <-- Names of data segments
		 * [Nonce_Bytes][Block_Bytes........][Block_Bytes] <-- Sizes of data segments
		 * [..........Buffer_Bytes.......................]
		 */
		u8_t *data;
	};

	TEMPLATE_ARGS
	CLASS::CTR_Mode (Block_Cipher_t *cipher, u8_t *ctr_data)
		: blk_cipher{ cipher }, data{ ctr_data }
	{
	}/* ~ CTR_Mode (Block_Cipher_t *,u8_t *) */

	TEMPLATE_ARGS
	void CLASS::set_nonce (u8_t const *nonce)
	{
		std::memcpy( data, nonce, Nonce_Bytes );
	}/* ~ void set_nonce (void*) */

	TEMPLATE_ARGS
	void CLASS::xorcrypt (u8_t *output, u8_t const *input, u64_t const input_size, u64_t start)
	{
		using std::memcpy, std::memset;
		u8_t * const keystream_plaintext = data + Nonce_Bytes;
		u8_t * const temp_buffer         = data + (Nonce_Bytes + Block_Bytes);
		u64_t        bytes_left = input_size;
		u64_t	     counter = start;

		// Zero the space between the counter and the nonce, given that the nonce is half the keystream plaintext.
		// [Keystream Plaintext]
		// [Counter][...][Nonce]
		if constexpr(sizeof(counter) != Nonce_Bytes)//if there is space between the counter and the nonce...
			memset( (keystream_plaintext + sizeof(counter)), 0, (Nonce_Bytes - sizeof(counter)) );
		// Copy the nonce into the second half of the keystream_plaintext.
		static_assert (Block_Bytes == Nonce_Bytes * 2);
		memcpy( (keystream_plaintext + Nonce_Bytes), data, Nonce_Bytes );
		static_assert (Nonce_Bytes > sizeof(u64_t));

		while (bytes_left >= Block_Bytes) {
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			blk_cipher->cipher( temp_buffer, keystream_plaintext );
			xor_block<Block_Bits>( temp_buffer, input );
			memcpy( out, temp_buffer, Block_Bytes );
			input      += Block_Bytes;
			output     += Block_Bytes;
			bytes_left -= Block_Bytes;
			++counter;
		}
		if (bytes_left > 0) {
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			blk_cipher->cipher( temp_buffer, keystream_plaintext );
			for (u64_t i = 0; i < bytes_left; ++i)
				temp_buffer[ i ] ^= input[ i ];
			memcpy( out, temp_buffer, bytes_left );
		}
	} /* ~ void xorcrypt(void*,void*,size_t,u64_t) */
}/*namespace ssc*/
#undef CLASS
#undef TEMPLATE_ARGS
