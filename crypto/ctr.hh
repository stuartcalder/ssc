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
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>

#include <utility>
#include <ssc/general/symbols.hh>
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

namespace ssc {
	TEMPLATE_ARGS
	class CTR_Mode {
		public:
			static_assert (CHAR_BIT == 8);
			/* Compile-Time Constants and checks*/
			static_assert (Block_Bits % CHAR_BIT == 0);
			static_assert (Block_Bits >= 128);
			static_assert (Block_Cipher_t::Block_Bits == Block_Bits);
			_CTIME_CONST(int)	Block_Bytes = Block_Bits / CHAR_BIT;
			static_assert (Block_Bytes % 2 == 0);
			_CTIME_CONST(int)	Nonce_Bytes = Block_Bytes / 2;
			_CTIME_CONST(int)	Buffer_Bytes = Nonce_Bytes + (Block_Bytes * 2);

			/* Public Interface */
			CTR_Mode (void) = delete;

			CTR_Mode (Block_Cipher_t *b_cipher, u8_t *ctr_data);

			template <typename... Args>
			CTR_Mode (Block_Cipher_t *b_cipher, u8_t *ctr_data, Args... args);

			inline void
			set_nonce (void const *nonce);

			void
			xorcrypt (void *output, void const *input, size_t const input_size, u64_t start = 0);
		private:
			Block_Cipher_t	*blk_cipher;
			u8_t		*random_nonce;
			u8_t		*scratch_buffer;
	};

	TEMPLATE_ARGS
	CLASS::CTR_Mode (Block_Cipher_t *cipher, u8_t *ctr_data)
		: blk_cipher{ cipher }, random_nonce{ ctr_data }, scratch_buffer{ ctr_data + Nonce_Bytes }
	{
	}

	TEMPLATE_ARGS
	void
	CLASS::set_nonce (void const *nonce) {
		std::memcpy( random_nonce, nonce, Nonce_Bytes );
	}

	TEMPLATE_ARGS
	void
	CLASS::xorcrypt (void *output, void const *input, size_t const input_size, u64_t start) {
		using std::memcpy, std::memset;
		u8_t		*keystream_plaintext = scratch_buffer;
		u8_t		*buffer              = scratch_buffer + Block_Bytes;
		size_t		bytes_left = input_size;
		u8_t const	*in = static_cast<u8_t const *>(input);
		u8_t		*out = static_cast<u8_t *>(output);
		u64_t		counter = start;

		// Zero the space between the counter and the nonce.
		if constexpr(sizeof(counter) != Nonce_Bytes)
			memset( (keystream_plaintext + sizeof(counter)), 0, (Nonce_Bytes - sizeof(counter)) );
		// Copy the nonce into the second half of the keystream_plaintext.
		static_assert(Block_Bytes == Nonce_Bytes * 2);
		memcpy( (keystream_plaintext + Nonce_Bytes), random_nonce, Nonce_Bytes );
		static_assert (Nonce_Bytes > sizeof(u64_t));

		while (bytes_left >= Block_Bytes) {
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			blk_cipher->cipher( buffer, keystream_plaintext );
			xor_block<Block_Bits>( buffer, in );
			memcpy( out, buffer, Block_Bytes );
			in         += Block_Bytes;
			out        += Block_Bytes;
			bytes_left -= Block_Bytes;
			++counter;
		}
		if (bytes_left > 0) {
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			blk_cipher->cipher( buffer, keystream_plaintext );
			for (int i = 0; i < static_cast<int>(bytes_left); ++i)
				buffer[ i ] ^= in[ i ];
			memcpy( out, buffer, bytes_left );
		}
	}
}/*namespace ssc*/
#undef CLASS
#undef TEMPLATE_ARGS
