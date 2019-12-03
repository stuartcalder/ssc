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
#include <climits>
#include <utility>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/memory/os_memory_locking.hh>

/* 
	Cipher_Block_Chaining < Block_Cipher_t, Block_Bits >
	This class implements The Cipher-Block-Chaining mode of operation for cryptographic block ciphers.
	Block_Cipher_t  =====> Some type that implements four specific methods:
	size_t encrypt(const u8_t *bytes_in, u8_t *bytes_out, const size_t size_in, const u8_t *iv);
	If IV is nullptr, the "state" is assumed to be already seeded with past invocations
	If IV is not nullptr, it is used to seed the state for encryption
	size_t decrypt(const u8_t *bytes_in, u8_t *bytes_out, const size_t size_in, const u8_t *iv);
	If IV is nullptr, the "state" is assumed to be already seeded with past invocations
	If IV is not nullptr, it is used to seed the state for encryption
	void   encrypt_no_padding(const u8_t *bytes_in, u8_t *bytes_out, const size_t size_in, const u8_t *iv);
	Same IV conditions as above ; does not do any sort of padding ; must only be used with buffers
	perfectly divisible by Block_Bits
	void   decrypt_no_padding(const u8_t *bytes_in, u8_t *bytes_out, const size_t size_in, const u8_t *iv);
	Same conditions as above.
	Block_Bits      =====> a size_t unsigned integer describing the number of bits in 1 block of the block cipher.
 */

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error "Already defined"
#endif

namespace ssc {
	template <typename Block_Cipher_t, int Block_Bits>
	class Cipher_Block_Chaining {
	public:
		/* COMPILE TIME CHECKS */
		static_assert	(CHAR_BIT == 8);
		static_assert	(Block_Bits % CHAR_BIT == 0);
		static_assert	(Block_Bits >= 128);
		static_assert	(Block_Cipher_t::Block_Bits == Block_Bits);
		/* COMPILE TIME CONSTANTS */
		CTIME_CONST(int)	Block_Bytes   = Block_Bits / CHAR_BIT;
		CTIME_CONST(int)	State_Bytes   = Block_Bytes;
		CTIME_CONST(int)	Scratch_Bytes = Block_Bytes * 2;
		CTIME_CONST(int)	Buffer_Bytes  = State_Bytes + Scratch_Bytes;
		/* PUBLIC INTERFACE */
		Cipher_Block_Chaining (void) = delete;
		Cipher_Block_Chaining (Block_Cipher_t *__restrict cipher, u8_t *__restrict buffer)
			: blk_cipher{ cipher }, state{ buffer }, scratch{ buffer + State_Bytes }
		{
		}
#if 0
		Cipher_Block_Chaining  (void) = delete;		/* Disallow construction with no arguments. */
		Cipher_Block_Chaining  (Block_Cipher_t &&blk_c);	/* Construct a Cipher_Block_Chaining object with the block cipher in-place. */
		Cipher_Block_Chaining  (u8_t const *);
		template <typename... Blk_Cipher_Args>
		Cipher_Block_Chaining  (u8_t const *, Blk_Cipher_Args...);
		~Cipher_Block_Chaining (void);			/* Destruct a Cipher_Block_Chaining object. (zero sensitive memory) */
#endif

#if 0
		void	manually_set_state (u8_t const *__restrict const state_bytes);
		void	encrypt_no_padding (u8_t const *bytes_in, u8_t *bytes_out, size_t const size_in, u8_t const *__restrict iv);
		void	decrypt_no_padding (u8_t const *bytes_in, u8_t *bytes_out, size_t const size_in, u8_t const *__restrict iv);
#endif
#if 0
		size_t	decrypt (u8_t const *bytes_in, u8_t *bytes_out, size_t const size_in, u8_t const *__restrict iv);
		size_t	encrypt (u8_t const *bytes_in, u8_t *bytes_out, size_t const size_in, u8_t const *__restrict iv);
#endif
		size_t	encrypt (u8_t *__restrict bytes_out, u8_t const *__restrict bytes_in, size_t const size_in, u8_t const *__restrict iv);
		size_t	decrypt	(u8_t *__restrict bytes_out, u8_t const *__restrict bytes_in, size_t const size_in, u8_t const *__restrict iv);
	private:
		/* PRIVATE STATE */
#if 0
		Block_Cipher_t  blk_cipher;
		u8_t		state [Block_Bytes] = { 0 };
#endif
		Block_Cipher_t	*blk_cipher;
		u8_t		*state;
		u8_t		*scratch;
		/* PRIVATE INTERFACE */

#if 0
		static size_t	apply_iso_iec_7816_padding_ (u8_t *bytes, size_t const prepadding_size);
#endif
		static size_t	count_iso_iec_7816_padding_bytes_ (u8_t const * const bytes, size_t const padded_size);
		static size_t	calculate_padded_ciphertext_size_ (size_t const unpadded_plaintext_size);
	}; /* Cipher_Block_Chaining */
	/* Constructors */
#if 0
	template <typename Block_Cipher_t, int Block_Bits>
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::Cipher_Block_Chaining (Block_Cipher_t &&blk_c) 
		: blk_cipher{ std::move( blk_c ) }
	{
#ifdef __SSC_MemoryLocking__
		lock_os_memory( state, sizeof(state) );
#endif
	}
	template <typename Block_Cipher_t, int Block_Bits>
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::Cipher_Block_Chaining (u8_t const *key)
		: blk_cipher{ key }
	{
#ifdef __SSC_MemoryLocking__
		lock_os_memory( state, sizeof(state) );
#endif
	}
	template <typename Block_Cipher_t, int Block_Bits>
	template <typename... Blk_Cipher_Args>
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::Cipher_Block_Chaining (u8_t const *key, Blk_Cipher_Args... args)
		: blk_cipher{ key, args... }
	{
#ifdef __SSC_MemoryLocking__
		lock_os_memory( state, sizeof(state) );
#endif
	}
	/* Destructors */
	template <typename Block_Cipher_t, int Block_Bits>
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::~Cipher_Block_Chaining (void) {
		zero_sensitive( state, sizeof(state) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( state, sizeof(state) );
#endif
	}
#endif

#if 0
	template <typename Block_Cipher_t, int Block_Bits>
	void
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::manually_set_state (u8_t const *__restrict const state_bytes) {
		std::memcpy( state, state_bytes, sizeof(state) );
	}
#endif

#if 0
	template <typename Block_Cipher_t, int Block_Bits>
	size_t
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::apply_iso_iec_7816_padding_ (u8_t *bytes, size_t const prepadding_size) {
		// Here, bytes_to_add is pre-emptively decremented by 1, as padding t least one byte is necessary for this padding scheme.
		using namespace std;
		size_t const bytes_to_add = (Block_Bytes - (prepadding_size % Block_Bytes) - 1);
		// The byte 0x80 precedes any null bytes (if any) that make up the padding.
		bytes[ prepadding_size ] = 0x80u;
		// Set the rest of the state to zero (if there is any state left to zero).
		memset( (bytes + prepadding_size + 1), 0x00u, bytes_to_add );
		return prepadding_size + 1 + bytes_to_add;
	}
#endif

	template <typename Block_Cipher_t, int Block_Bits>
	size_t
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::count_iso_iec_7816_padding_bytes_ (u8_t const * const bytes, size_t const padded_size) {
		using namespace std;
		size_t i = padded_size - 1, count = 0;
		for (; i <= padded_size; --i) {
			++count;
			if (bytes[ i ] == 0x80)
				return count;
		}
		errx( "Error: Invalid Cipher_Block_Chaining padding\n" );
	}

        template <typename Block_Cipher_t, int Block_Bits>
	size_t
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::calculate_padded_ciphertext_size_ (size_t const unpadded_plaintext_size) {
		return unpadded_plaintext_size + (Block_Bytes - (unpadded_plaintext_size % Block_Bytes));
	}

#if 0
        template <typename Block_Cipher_t, int Block_Bits>
	void
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::encrypt_no_padding (u8_t const *bytes_in, u8_t *bytes_out, size_t const size_in, u8_t const * __restrict iv) {
		using std::memcpy;

		if (iv != nullptr)
			memcpy( state, iv, sizeof(state) );
		if (bytes_in != bytes_out)
			memcpy( bytes_out, bytes_in, size_in );
		size_t const last_block_offset = size_in - Block_Bytes;
		for (size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes) {
			u8_t *current_block = bytes_out + b_off;
			xor_block<Block_Bits>( current_block, state );
			blk_cipher.cipher( current_block, current_block );
			memcpy( state, current_block, sizeof(state) );
		}
	}
#endif

        template <typename Block_Cipher_t, int Block_Bits>
	size_t
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::encrypt (u8_t *bytes_out, u8_t const *bytes_in, size_t const size_in, u8_t const * __restrict iv) {
		using std::memcpy;
#if 0
		// If an IV was supplied, copy it into the state
		if (iv != nullptr)
			memcpy( state, iv, sizeof(state) );
#endif
		if (iv != nullptr)
			memcpy( state, iv, State_Bytes );
		u8_t const	*in  = bytes_in;
		u8_t		*out = bytes_out;
		size_t		bytes_left = size_in;

#if 0
		u8_t buffer [Block_Bytes];
#ifdef __SSC_MemoryLocking__
		lock_os_memory( buffer, sizeof(buffer) );
#endif

		static_assert (sizeof(state)  == Block_Bytes);
		static_assert (sizeof(buffer) == Block_Bytes);
		while (bytes_left >= Block_Bytes) {
			memcpy( buffer, in, Block_Bytes );
			xor_block<Block_Bits>( buffer, state );
			blk_cipher.cipher( state, buffer );
			memcpy( out, state, Block_Bytes );

			in         += Block_Bytes;
			out        += Block_Bytes;
			bytes_left -= Block_Bytes;
		}
#endif
		while (bytes_left >= Block_Bytes) {
			memcpy( scratch, in, Block_Bytes );
			xor_block<Block_Bits>( scratch, state );
			blk_cipher->cipher( state, scratch );
			memcpy( out, state, Block_Bytes );

			in         += Block_Bytes;
			out        += Block_Bytes;
			bytes_left -= Block_Bytes;
		}
#if 0
		// Padding Plaintext before a final encrypt
		memcpy( buffer, in, bytes_left );
		buffer[ bytes_left ] = 0x80;
		memset( (buffer + bytes_left + 1), 0, (Block_Bytes - (bytes_left + 1)) );
#endif
		memcpy( scratch, in, bytes_left );
		scratch[ bytes_left ] = 0x80;
#if 0
		memset( (scratch + bytes_left + 1), 0, (Block_Bytes - (bytes_left + 1)) );
#endif
		memset( (scratch + bytes_left + 1), 0, ((Block_Bytes - 1) - bytes_left) );
		// Final encrypt
#if 0
		xor_block<Block_Bits>( buffer, state );
		blk_cipher.cipher( state, buffer );
		memcpy( out, state, Block_Bytes );
#endif
		xor_block<Block_Bits>( scratch, state );
		blk_cipher->cipher( state, scratch );
		memcpy( out, state, Block_Bytes );

#if 0
		zero_sensitive( buffer, Block_Bytes );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( buffer, sizeof(buffer) );
#endif
#endif
		return calculate_padded_ciphertext_size_( size_in );
	} /* ! encrypt */

        template <typename Block_Cipher_t, int Block_Bits>
	size_t
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::decrypt (u8_t *bytes_out, u8_t const *bytes_in, size_t const size_in, u8_t const *__restrict iv) {
		using std::memcpy;

#if 0
		if (iv != nullptr)
			memcpy( state, iv, sizeof(state) );
		size_t const last_block_offset = (size_in >= Block_Bytes) ? (size_in - Block_Bytes) : 0;
#endif
		if (iv != nullptr)
			memcpy( state, iv, State_Bytes );
		size_t const last_block_offset = ((size_in >= Block_Bytes) ? (size_in - Block_Bytes) : 0);

#if 0
		u8_t ciphertext [Block_Bytes];
		u8_t buffer     [Block_Bytes];
#ifdef __SSC_MemoryLocking__
		lock_os_memory( ciphertext, sizeof(ciphertext) );
		lock_os_memory( buffer    , sizeof(buffer)     );
#endif
#endif
		u8_t * const ciphertext = scratch;
		u8_t * const buffer     = scratch + Block_Bytes;

#if 0
		for (size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes) {
			u8_t const *block_in  = bytes_in  + b_off;
			u8_t *block_out = bytes_out + b_off;
			memcpy( ciphertext, block_in, Block_Bytes );
			blk_cipher.inverse_cipher( buffer, ciphertext );
			xor_block<Block_Bits>( buffer, state );
			memcpy( block_out, buffer    , Block_Bytes );
			memcpy( state    , ciphertext, Block_Bytes );
		}
#endif
		for (size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes) {
			u8_t const	*block_in  = bytes_in  + b_off;
			u8_t		*block_out = bytes_out + b_off;
			memcpy( ciphertext, block_in, Block_Bytes );
			blk_cipher->inverse_cipher( buffer, ciphertext );
			xor_block<Block_Bits>( buffer, state );
			memcpy( block_out, buffer    , Block_Bytes );
			memcpy( state    , ciphertext, Block_Bytes );
		}

#if 0
		zero_sensitive( ciphertext, Block_Bytes );
		zero_sensitive( buffer    , Block_Bytes );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( ciphertext, sizeof(ciphertext) );
		unlock_os_memory( buffer    , sizeof(buffer)     );
#endif
#endif
		return size_in - count_iso_iec_7816_padding_bytes_( bytes_out, size_in );
	}
#if 0
        template <typename Block_Cipher_t, int Block_Bits>
	void
	Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>::decrypt_no_padding (u8_t const *bytes_in, u8_t *bytes_out, size_t const size_in, u8_t const * __restrict iv) {
		using std::memcpy;

		if (iv != nullptr)
			memcpy( state, iv, sizeof(state) );
		size_t const last_block_offset = size_in - Block_Bytes;
		u8_t ciphertext [Block_Bytes];
		u8_t buffer     [Block_Bytes];
		static_assert (sizeof(state)      == Block_Bytes);
		static_assert (sizeof(ciphertext) == Block_Bytes);
		static_assert (sizeof(buffer)     == Block_Bytes);
		for (size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes) {
			u8_t const *block_in  = bytes_in  + b_off;
			u8_t *block_out = bytes_out + b_off;
			memcpy( ciphertext, block_in, Block_Bytes );
			blk_cipher.inverse_cipher( buffer, ciphertext );
			xor_block<Block_Bits>( buffer, state );
			memcpy( block_out, buffer    , Block_Bytes );
			memcpy( state    , ciphertext, Block_Bytes );
		}
		zero_sensitive( buffer    , Block_Bytes );
		zero_sensitive( ciphertext, Block_Bytes );
	}
#endif
}/* ! namespace ssc */
#undef CTIME_CONST
