/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
#include <cstdio>
#include <cstdlib>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#define	CHANGE true

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS template <int State_Bits>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif
#ifndef CLASS
#	define CLASS Unique_Block_Iteration<State_Bits>
#else
#	error 'CLASS Already Defined'
#endif

namespace ssc
{
	TEMPLATE_ARGS
	class Unique_Block_Iteration
	{
	public:
	/* Compile-Time checks, Constants, and Aliases */
		static_assert (CHAR_BIT == 8);
		static_assert (State_Bits  % CHAR_BIT == 0);
		using Threefish_t = Threefish<State_Bits>;

		_CTIME_CONST (int) State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST (int) Msg_Bytes = State_Bytes;
		static_assert (State_Bytes % CHAR_BIT == 0);
		_CTIME_CONST (int) Tweak_Bits = 128;
		_CTIME_CONST (int) Tweak_Bytes = Tweak_Bits / CHAR_BIT;
		_CTIME_CONST (int) Buffer_Bytes = (Msg_Bytes + Threefish_t::External_Key_Buffer_Bytes + Threefish_t::External_Tweak_Buffer_Bytes);
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
#ifdef CHANGE
		Unique_Block_Iteration (void) = delete;
		Unique_Block_Iteration (Threefish_t *tf, u8_t *buffer)
			: threefish  { tf },
			  key_state  { buffer },
			  msg_state  { buffer + Threefish_t::External_Key_Buffer_Bytes },
			  tweak_state{ buffer + (Threefish_t::External_Key_Buffer_Bytes + State_Bytes) }
		{
		}
#else
		Unique_Block_Iteration (void) = delete;
		Unique_Block_Iteration (Tweakable_Block_Cipher_t *tbc, u8_t *buffer)
			: twk_blk_cipher{ tbc },
			  tweak_state{ buffer                               },
			  key_state  { buffer + Tweak_Bytes                 },
			  msg_state  { buffer + (Tweak_Bytes + State_Bytes) }
		{
		}
#endif
	/* Public Interface */
		void          chain (Type_Mask_E const type_mask, u8_t const * const message, u64_t const message_size);
		inline u8_t * get_key_state (void);
		inline void   clear_key_state (void);
	private:
	/* Private Compile-Time constants */
	/* Private Data */
#ifdef CHANGE
		Threefish_t		 * const threefish;
#else
		Tweakable_Block_Cipher_t * const twk_blk_cipher;
#endif
		u8_t			 * const key_state;
		u8_t			 * const msg_state;
		u8_t			 * const tweak_state;
	/* Private Interface */
		inline void set_tweak_first_ (void);

		inline void set_tweak_last_ (void);

		inline void clear_tweak_first_ (void);

		inline void clear_tweak_last_ (void);

		inline void set_tweak_type_ (Type_Mask_E const t_mask);

		u64_t       read_msg_block_ (u8_t const * const message_offset, u64_t const bytes_left);
	}; /* ~ class Unique_Block_Iteration */

	TEMPLATE_ARGS
	void CLASS::chain (Type_Mask_E const type_mask, u8_t const * const message, u64_t const message_size)
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
#ifdef CHANGE
		threefish->rekey( key_state, tweak_state );
#else
		twk_blk_cipher->rekey( key_state, tweak_state );
#endif
		// First block
#ifdef CHANGE
		threefish->cipher( key_state, msg_state );
#else
		twk_blk_cipher->cipher( key_state, msg_state );
#endif
		xor_block<State_Bits>( key_state, msg_state );
		clear_tweak_first_();
		// Intermediate blocks (assuming first block wasn't also the last block)
		while (message_bytes_left > State_Bytes ) {
			bytes_just_read = read_msg_block_( message_offset, message_bytes_left );
			message_offset      += bytes_just_read;
			message_bytes_left -= bytes_just_read;
			(*position)         += bytes_just_read;
#ifdef CHANGE
			threefish->rekey( key_state, tweak_state );
			threefish->cipher( key_state, msg_state );
#else
			twk_blk_cipher->rekey( key_state, tweak_state );
			twk_blk_cipher->cipher( key_state, msg_state );
#endif
			xor_block<State_Bits>( key_state, msg_state );
		}
		// Last block (assuming first block wasn't also the last block)
		if (message_bytes_left > 0) {
			set_tweak_last_();
			(*position) += read_msg_block_( message_offset, message_bytes_left );
#ifdef CHANGE
			threefish->rekey( key_state, tweak_state );
			threefish->cipher( key_state, msg_state );
#else
			twk_blk_cipher->rekey( key_state, tweak_state );
			twk_blk_cipher->cipher( key_state, msg_state );
#endif
			xor_block<State_Bits>( key_state, msg_state );
		}
	} /* ~ chain */

	TEMPLATE_ARGS
	void CLASS::set_tweak_first_ (void)
	{
		tweak_state[ Tweak_Bytes - 1 ] |= 0b0100'0000;
	} /* ~ set_tweak_first_ */

	TEMPLATE_ARGS
	void CLASS::set_tweak_last_ (void)
	{
		tweak_state[ Tweak_Bytes - 1 ] |= 0b1000'0000;
	} /* ~ set_tweak_last_ */

	TEMPLATE_ARGS
	void CLASS::clear_tweak_first_ (void)
	{
		tweak_state[ Tweak_Bytes - 1 ] &= 0b1011'1111;
	} /* ~ clear_tweak_first_ */

	TEMPLATE_ARGS
	void CLASS::clear_tweak_last_ (void)
	{
		tweak_state[ Tweak_Bytes - 1 ] &= 0b0111'1111;
	} /* ~ clear_tweak_last_ */

	TEMPLATE_ARGS
	void CLASS::set_tweak_type_ (Type_Mask_E const type_mask)
	{
		tweak_state[ Tweak_Bytes - 1 ] |= static_cast<u8_t>(type_mask);
	} /* ~ set_tweak_type_ */

	TEMPLATE_ARGS
	u64_t CLASS::read_msg_block_ (u8_t const * const message_offset, u64_t const bytes_left)
	{
		static_assert (State_Bytes == Msg_Bytes);
		u64_t bytes_read;

		if (bytes_left >= State_Bytes) {
			std::memcpy( msg_state, message_offset, State_Bytes );
			bytes_read = State_Bytes;
		} else {
			std::memcpy( msg_state, message_offset, bytes_left );
			std::memset( (msg_state + bytes_left), 0, (Msg_Bytes - bytes_left) );
			bytes_read = bytes_left;
		}
		return bytes_read;
	} /* ~ read_msg_block_ */

	TEMPLATE_ARGS
	u8_t * CLASS::get_key_state (void)
	{
		return key_state;
	} /* ~ get_key_state */

	TEMPLATE_ARGS
	void CLASS::clear_key_state (void)
	{
		std::memset( key_state, 0, State_Bytes );
	} /* ~ clear_key_state */
}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
