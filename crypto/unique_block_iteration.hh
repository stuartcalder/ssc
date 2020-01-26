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
#include <cstdio>
#include <cstdlib>
#include <ssc/crypto/operations.hh>
#if 0 // Seemingly unneeded now.
#	include <ssc/memory/os_memory_locking.hh>
#endif
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error 'Already defined'
#endif

namespace ssc {
	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	class Unique_Block_Iteration {
	public:
	/* Compile-Time checks, Constants, and Aliases */
		static_assert		(CHAR_BIT == 8);
		static_assert		(State_Bits  % CHAR_BIT == 0);
		CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
		CTIME_CONST(int)	Msg_Bytes   = State_Bytes;
		static_assert		(State_Bytes % CHAR_BIT == 0);
		CTIME_CONST(int)	Tweak_Bits  = 128;
		CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;
		CTIME_CONST(int)	Buffer_Bytes = (Tweak_Bytes + State_Bytes + Msg_Bytes);
		enum class Type_Mask_E : u8_t {
			T_key = 0,
			T_cfg = 4,
			T_prs = 8,
			T_pk  = 12,
			T_kdf = 16,
			T_non = 20,
			T_msg = 48,
			T_out = 63
		};
	/* Constructors / Destructors */
		Unique_Block_Iteration (void) = delete;
		Unique_Block_Iteration (Tweakable_Block_Cipher_t *tbc, u8_t *buffer)
			: twk_blk_cipher{ tbc },
			  tweak_state{ buffer                               },
			  key_state  { buffer + Tweak_Bytes                 },
			  msg_state  { buffer + (Tweak_Bytes + State_Bytes) }
		{
		}
	/* Public Interface */
		void
		chain	(Type_Mask_E const  type_mask,
		  	 u8_t const * const message,
			 u64_t const        message_size);

		u8_t *
		get_key_state	(void);

		void
		clear_key_state	(void);
	private:
	/* Private Compile-Time constants */
	/* Private Data */
		Tweakable_Block_Cipher_t * const twk_blk_cipher;
		u8_t			 * const tweak_state;
		u8_t			 * const key_state;
		u8_t			 * const msg_state;
	/* Private Interface */
		inline void
		set_tweak_first_	(void);

		inline void
		set_tweak_last_		(void);

		inline void
		clear_tweak_first_	(void);

		inline void
		clear_tweak_last_	(void);

		inline void
		set_tweak_type_		(Type_Mask_E const t_mask);

		u64_t
		read_msg_block_		(u8_t const * const message_offset,
					 u64_t const        bytes_left);
	}; /* class Unique_Block_Iteration */

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::chain (Type_Mask_E const  type_mask,
									    u8_t const * const message,
									    u64_t const        message_size)
	{
		using namespace std;
		u8_t const	*message_offset = message;
		// Setup the tweak
		memset( tweak_state, 0, Tweak_Bytes );
		set_tweak_type_( type_mask );
		set_tweak_first_();
		// Setup initial key and message state
		// Get message
		u64_t	message_bytes_left = message_size;
		u64_t	bytes_just_read    = read_msg_block_( message_offset, message_bytes_left );
		message_offset     += bytes_just_read;
		message_bytes_left -= bytes_just_read;
		if (message_bytes_left == 0)
			set_tweak_last_();
		// Set the position, and get a pointer to it for use later.
		u64_t	* const position = reinterpret_cast<u64_t *>(tweak_state);
		(*position) = bytes_just_read;
		// First block setup
		twk_blk_cipher->rekey( key_state, tweak_state );
		// First block
		twk_blk_cipher->cipher( key_state, msg_state );
		xor_block<State_Bits>( key_state, msg_state );
		clear_tweak_first_();
		// Intermediate blocks (assuming first block wasn't also the last block)
		while (message_bytes_left > State_Bytes ) {
			bytes_just_read = read_msg_block_( message_offset, message_bytes_left );
			message_offset      += bytes_just_read;
			message_bytes_left -= bytes_just_read;
			(*position)         += bytes_just_read;
			twk_blk_cipher->rekey( key_state, tweak_state );
			twk_blk_cipher->cipher( key_state, msg_state );
			xor_block<State_Bits>( key_state, msg_state );
		}
		// Last block (assuming first block wasn't also the last block)
		if (message_bytes_left > 0) {
			set_tweak_last_();
			(*position) += read_msg_block_( message_offset, message_bytes_left );
			twk_blk_cipher->rekey( key_state, tweak_state );
			twk_blk_cipher->cipher( key_state, msg_state );
			xor_block<State_Bits>( key_state, msg_state );
		}
	} /* chain */

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::set_tweak_first_ (void) {
		tweak_state[ Tweak_Bytes - 1 ] |= 0b0100'0000;
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::set_tweak_last_ (void) {
		tweak_state[ Tweak_Bytes - 1 ] |= 0b1000'0000;
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::clear_tweak_first_ (void) {
		tweak_state[ Tweak_Bytes - 1 ] &= 0b1011'1111;
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::clear_tweak_last_ (void) {
		tweak_state[ Tweak_Bytes - 1 ] &= 0b0111'1111;
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::set_tweak_type_ (Type_Mask_E const type_mask) {
		tweak_state[ Tweak_Bytes - 1 ] |= static_cast<u8_t>(type_mask);
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	u64_t
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::read_msg_block_ (u8_t const * const message_offset,
										      u64_t const        bytes_left)
	{
		u64_t bytes_read;
		static_assert	(State_Bytes == Msg_Bytes);

		if (bytes_left >= State_Bytes) {
			std::memcpy( msg_state, message_offset, State_Bytes );
			bytes_read = State_Bytes;
		} else {
			std::memset( msg_state, 0, Msg_Bytes );
			std::memcpy( msg_state, message_offset, bytes_left );
			bytes_read = bytes_left;
		}
		return bytes_read;
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	u8_t *
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::get_key_state (void) {
		return key_state;
	}

	template <typename Tweakable_Block_Cipher_t, int State_Bits>
	void
	Unique_Block_Iteration<Tweakable_Block_Cipher_t,State_Bits>::clear_key_state (void) {
		std::memset( key_state, 0, State_Bytes );
	}
}/* ! namespace ssc */
#undef CTIME_CONST
