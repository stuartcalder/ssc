/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
#include <climits>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>

namespace ssc {
	template <size_t State_Bits, bool Sensitive = true>
	class Skein {
	public:
		/* PUBLIC CONSTANTS and COMPILE-TIME CHECKS */
		static_assert	(CHAR_BIT == 8);
		static_assert	(State_Bits == 256 || State_Bits == 512 || State_Bits == 1024);

		using Threefish_t = Threefish<State_Bits>;
		using UBI_t	  = Unique_Block_Iteration<Threefish_t, State_Bits>;
		using Type_Mask_E = typename UBI_t::Type_Mask_E;

		_CTIME_CONST(size_t)	State_Bytes = State_Bits / CHAR_BIT;

		/* PUBLIC INTERFACE */
		Skein (void) = delete;
		Skein (UBI_t *u)
			: ubi{ u }
		{
		}

		// Receive output bytes and output pseudorandom bytes from the hash function.
		void
		hash (u8_t * const         bytes_out,
		      u8_t const * const   bytes_in,
		      u64_t const          num_bytes_in,
		      u64_t const          num_bytes_out = State_Bytes);

		// Authenticate the input bytes with the input key.
		void
		message_auth_code (u8_t * const         bytes_out,
		                   u8_t const * const   bytes_in,
		                   u8_t const * const   key_in,
		                   u64_t const          num_bytes_in,
		                   u64_t const          num_key_bytes_in,
		                   u64_t const          num_bytes_out = State_Bytes);

		// Hash the input bytes, outputting State_Bytes pseudorandom bytes.
		void
		hash_native (u8_t * const         bytes_out,
		             u8_t const * const   bytes_in,
		             u64_t const          num_bytes_in);
	private:
		/* PRIVATE DATA */
		UBI_t	*ubi;
		
		/* PRIVATE INTERFACE */
		void
		process_config_block_ (u64_t const num_output_bits);

		inline void
		process_key_block_ (u8_t const * const   key_in,
				    u64_t const          key_size);

		inline void
		process_message_block_ (u8_t const * const   message_in,
				        u64_t const          message_size);

		void
		output_transform_ (u8_t        *out,
				   u64_t const num_output_bytes);
	}; /* ! Skein */
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::process_config_block_ (u64_t const num_output_bits) {
		/* Setup configuration string. */
		u8_t config [32] = {
			// First 4 bytes
			0x53, 0x48, 0x41, 0x33, // Schema identifier "SHA3"
			// Next 2 bytes
			0x01, 0x00,             // Version number (1)
			// Next 2 bytes
			0x00, 0x00,             // Reserved (0)
			// Next 8 bytes
			0x00, 0x00, 0x00, 0x00, // Output length
			0x00, 0x00, 0x00, 0x00,
			// Remaining 16 bytes
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};
		std::memcpy( config + 8, &num_output_bits, sizeof(num_output_bits) );
		ubi->chain( Type_Mask_E::T_cfg, config, sizeof(config) );
	} /* process_config_block_ */
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::process_key_block_ (u8_t const * const key_in,
			                                 u64_t const        key_size)
	{
		ubi->chain( Type_Mask_E::T_key, key_in, key_size );
	}
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::process_message_block_ (u8_t const * const message_in,
			                                     u64_t const        message_size)
	{
		ubi->chain( Type_Mask_E::T_msg, message_in, message_size );
	}
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::output_transform_ (u8_t		*out,
			                                u64_t const	num_output_bytes)
	{
		u64_t bytes_left = num_output_bytes;
		u64_t i = 0;
		while (true) {
			ubi->chain( Type_Mask_E::T_out, reinterpret_cast<u8_t *>(&i), sizeof(i) );
			++i;
			if (bytes_left >= State_Bytes) {
				std::memcpy( out, ubi->get_key_state(), State_Bytes );
				out        += State_Bytes;
				bytes_left -= State_Bytes;
			} else {
				std::memcpy( out, ubi->get_key_state(), bytes_left );
				break;
			}
		}
	}/* ! output_transform(...) */
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::hash (u8_t * const		bytes_out,
				           u8_t const * const	bytes_in,
				           u64_t const		num_bytes_in,
				           u64_t const		num_bytes_out)
	{
		if (num_bytes_out == 0)
			return;
		ubi->clear_key_state();
		static_assert (CHAR_BIT == 8);
		process_config_block_( num_bytes_out * CHAR_BIT );
		process_message_block_( bytes_in, num_bytes_in );
		output_transform_( bytes_out, num_bytes_out );
	}
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::message_auth_code	(u8_t * const       bytes_out,
						 	 u8_t const * const bytes_in,
							 u8_t const * const key_in,
							 u64_t const        num_bytes_in,
							 u64_t const        num_key_bytes_in,
							 u64_t const        num_bytes_out)
	{
		if (num_bytes_out == 0)
			return;
		ubi->clear_key_state();
		process_key_block_( key_in, num_key_bytes_in );
		static_assert (CHAR_BIT == 8);
		process_config_block_( num_bytes_out * CHAR_BIT );
		process_message_block_( bytes_in, num_bytes_in );
		output_transform_( bytes_out, num_bytes_out );
	}
    
	template <size_t State_Bits, bool Sensitive>
	void
	Skein<State_Bits,Sensitive>::hash_native	(u8_t * const       bytes_out,
							 u8_t const * const bytes_in,
							 u64_t const        num_bytes_in)
	{
		static_assert (State_Bits == 256 ||
		               State_Bits == 512 ||
		               State_Bits == 1024,
		               "Skein is only defined for 256, 512, 1024 bit-widths");
		if constexpr(State_Bits == 256) {
			static constexpr u64_t const init_chain [4] = {
				0xfc'9d'a8'60'd0'48'b4'49,
				0x2f'ca'66'47'9f'a7'd8'33,
				0xb3'3b'c3'89'66'56'84'0f,
				0x6a'54'e9'20'fd'e8'da'69
			};
			std::memcpy( ubi->get_key_state(), init_chain, sizeof(init_chain) );
		} else if constexpr(State_Bits == 512) {
			static constexpr u64_t const init_chain [8] = {
				0x49'03'ad'ff'74'9c'51'ce,
				0x0d'95'de'39'97'46'df'03,
				0x8f'd1'93'41'27'c7'9b'ce,
				0x9a'25'56'29'ff'35'2c'b1,
				0x5d'b6'25'99'df'6c'a7'b0,
				0xea'be'39'4c'a9'd5'c3'f4,
				0x99'11'12'c7'1a'75'b5'23,
				0xae'18'a4'0b'66'0f'cc'33
			};
			std::memcpy( ubi->get_key_state(), init_chain, sizeof(init_chain) );
		} else if constexpr(State_Bits == 1024) {
			static constexpr u64_t const init_chain[16] = {
				0xd5'93'da'07'41'e7'23'55, // 0
				0x15'b5'e5'11'ac'73'e0'0c, // 1
				0x51'80'e5'ae'ba'f2'c4'f0, // 2
				0x03'bd'41'd3'fc'bc'af'af, // 3
				0x1c'ae'c6'fd'19'83'a8'98, // 4
				0x6e'51'0b'8b'cd'd0'58'9f, // 5
				0x77'e2'bd'fd'c6'39'4a'da, // 6
				0xc1'1e'1d'b5'24'dc'b0'a3, // 7
				0xd6'd1'4a'f9'c6'32'9a'b5, // 8
				0x6a'9b'0b'fc'6e'b6'7e'0d, // 9
				0x92'43'c6'0d'cc'ff'13'32, //10
				0x1a'1f'1d'de'74'3f'02'd4, //11
				0x09'96'75'3c'10'ed'0b'b8, //12
				0x65'72'dd'22'f2'b4'96'9a, //13
				0x61'fd'30'62'd0'0a'57'9a, //14
				0x1d'e0'53'6e'86'82'e5'39  //15
			};
			std::memcpy( ubi->get_key_state(), init_chain, sizeof(init_chain) );
		}
		process_message_block_( bytes_in, num_bytes_in );
		output_transform_( bytes_out, State_Bytes );
	} /* hash_native */
} /* ! namespace ssc */
