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

namespace ssc {
	template <typename Block_Cipher_t, size_t Block_Bits>
	class CounterMode {
		public:
			static_assert (CHAR_BIT == 8);
			/* Compile-Time Constants and checks*/
			static_assert (Block_Bits % CHAR_BIT == 0);
			static_assert (Block_Bits >= 128);
			static_assert (Block_Cipher_t::Block_Bits == Block_Bits);
			static constexpr size_t const Block_Bytes = Block_Bits / CHAR_BIT;
			static_assert (Block_Bytes % 2 == 0);
			static constexpr size_t const Nonce_Bytes = Block_Bytes / 2;

			/* Public Interface */
			CounterMode (void) = delete;

			CounterMode (Block_Cipher_t *cipher_p);

			CounterMode (Block_Cipher_t *cipher_p, void const *nonce);

			inline void
			set_nonce (void const *nonce);

			void
			xorcrypt (void *output, void const *input, size_t const input_size, u64_t start = 0);
		private:
			Block_Cipher_t	*blk_cipher_p;
			byte_t		random_nonce	[Nonce_Bytes];
	};

	template <typename Block_Cipher_t, size_t Block_Bits>
	CounterMode<Block_Cipher_t,Block_Bits>::CounterMode (Block_Cipher_t *cipher_p)
		: blk_cipher_p{ cipher_p }
	{
		obtain_os_entropy( random_nonce, sizeof(random_nonce) );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	CounterMode<Block_Cipher_t,Block_Bits>::CounterMode (Block_Cipher_t *cipher_p, void const *nonce)
		: blk_cipher_p{ cipher_p }
	{
		set_nonce( nonce );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	void
	CounterMode<Block_Cipher_t,Block_Bits>::set_nonce (void const *nonce) {
		std::memcpy( random_nonce, nonce, sizeof(random_nonce) );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	void
	CounterMode<Block_Cipher_t,Block_Bits>::xorcrypt (void *output, void const *input, size_t const input_size, u64_t start) {
		using std::memcpy, std::memset;
		byte_t		keystream_plaintext	[Block_Bytes];
		byte_t		buffer			[Block_Bytes];
		size_t		bytes_left = input_size;
		byte_t const	*in  = static_cast<byte_t const *>(input);
		byte_t		*out = static_cast<byte_t *>(output);
		u64_t		counter = start;

#ifdef __SSC_MemoryLocking__
		lock_os_memory( buffer, sizeof(buffer) );
#endif

		// Zero the space between the counter and the nonce.
		if constexpr(sizeof(counter) != Nonce_Bytes)
			memset( (keystream_plaintext + sizeof(counter)), 0, (Nonce_Bytes - sizeof(counter)) );
		// Copy the nonce into the second half of the keystream_plaintext.
		static_assert (sizeof(keystream_plaintext)    == Nonce_Bytes * 2);
		static_assert (sizeof(random_nonce) == Nonce_Bytes);
		memcpy( (keystream_plaintext + Nonce_Bytes), random_nonce, sizeof(random_nonce) );
		static_assert (Nonce_Bytes > sizeof(u64_t));

		while (bytes_left >= Block_Bytes) {
			// Copy the counter into the keystream_plaintext.
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			// Encrypt a block of keystream_plaintext.
			blk_cipher_p->cipher( buffer, keystream_plaintext );
			// xor that block of keystream_plaintext with a block of inputtext.
			xor_block<Block_Bits>( buffer, in );
			// Copy the post-xor-text out.
			memcpy( out, buffer, sizeof(buffer) );

			// Advance the input and output pointers, reduce the bytes_left counter,
			// increment the keystream_plaintext counter.
			in         += Block_Bytes;
			out        += Block_Bytes;
			bytes_left -= Block_Bytes;
			++counter;
		}
		// There is now less than one block left to xorcrypt.
		if (bytes_left > 0) {
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			// Encrypt the last block to xor with.
			blk_cipher_p->cipher( buffer, keystream_plaintext );
			// For each byte left, xor them all together.
			for (int i = 0; i < static_cast<int>(bytes_left); ++i)
				buffer[ i ] ^= in[ i ];
			// Copy the post-xor-text out.
			memcpy( out, buffer, bytes_left );
		}
		zero_sensitive( buffer, sizeof(buffer) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( buffer, sizeof(buffer) );
#endif

	}
}/*namespace ssc*/
