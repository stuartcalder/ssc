/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <shim/macros.h>
#include <shim/errors.h>
#include <shim/operations.h>

/* SSC General
 */
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/error_conditions.hh>
/* SSC Crypto
 */
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish_f.hh>
/* C Std
 */
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>
/* C++ Std
 */
#include <utility>

#if    defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'Some MACRO needed was already defined!'
#endif
#define TEMPLATE_ARGS	template <int Block_Bits>
#define CLASS		Counter_Mode_F<Block_Bits>

namespace ssc
{
	TEMPLATE_ARGS class
	Counter_Mode_F
	{
	public:
		static_assert (CHAR_BIT == 8,
			       "A byte must be 8 bits.");
		static_assert ((Block_Bits % CHAR_BIT) == 0,
			       "The number of bits must be divisible into bytes.");
		static_assert ((Block_Bits >= 128),
			       "Modern block ciphers have blocks of at least 128 bits.");
		static constexpr int Block_Bytes = Block_Bits / CHAR_BIT;
		static_assert ((Block_Bytes % 2) == 0,
			       "Block bytes must be evenly divisible in half.");
		static constexpr int IV_Bytes = Block_Bytes / 2;
		using Threefish_f = Threefish_F<Block_Bits,Key_Schedule_E::Stored>;
		using Threefish_Data_t = typename Threefish_f::Data_t;
		struct Data {
			Threefish_Data_t          threefish_data;
			alignas(uint64_t) uint8_t keystream [Block_Bytes];
			alignas(uint64_t) uint8_t buffer    [Block_Bytes];
		};

		Counter_Mode_F (void) = delete;

		static inline void
		set_iv (Data *          SHIM_RESTRICT data,
			uint8_t const * SHIM_RESTRICT iv);

		static void
		xorcrypt (Data * SHIM_RESTRICT data,
			  uint8_t *            output,
			  uint8_t const *      input,
			  uint64_t             input_size,
			  uint64_t             starting_byte = 0);
	};

	TEMPLATE_ARGS void
	CLASS::set_iv (Data *          SHIM_RESTRICT data,
		       uint8_t const * SHIM_RESTRICT iv)
	{
		static_assert (Block_Bytes == (IV_Bytes *2));
		static_assert (sizeof(uint64_t) <= IV_Bytes);
		if constexpr (sizeof(uint64_t) != IV_Bytes)
			std::memset( (data->keystream + sizeof(uint64_t)), 0, (IV_Bytes - sizeof(uint64_t)) );
		std::memcpy( (data->keystream + IV_Bytes),
			     iv,
			     IV_Bytes );
	}

	TEMPLATE_ARGS void
	CLASS::xorcrypt (Data * SHIM_RESTRICT data,
			 uint8_t *            output,
			 uint8_t const *      input,
			 uint64_t             input_size,
			 uint64_t             starting_byte)
	{
		if( starting_byte == 0 ) {
			std::memcpy( data->keystream, &starting_byte, sizeof(starting_byte) );
		} else {
			uint64_t starting_block = starting_byte / Block_Bytes;
			uint64_t offset         = starting_byte % Block_Bytes;
			uint64_t bytes          = Block_Bytes - offset;
			std::memcpy( data->keystream, &starting_block, sizeof(starting_block) );
			Threefish_f::cipher( &data->threefish_data,
					     data->buffer,
					     data->keystream );
			{
				uint64_t temp;
				std::memcpy( &temp, data->keystream, sizeof(uint64_t) );
				++temp;
				std::memcpy( data->keystream, &temp, sizeof(temp) );
			}
			uint8_t *offset_buffer = data->buffer + offset;
			uint64_t left;
			if( input_size >= bytes )
				left = bytes;
			else
				left = input_size;
			for( uint64_t i = 0; i < left; ++i )
				offset_buffer[ i ] ^= input[ i ];
			std::memcpy( output, offset_buffer, left );
			input      += left;
			output     += left;
			input_size -= left;
		}
		while( input_size >= Block_Bytes ) {
			Threefish_f::cipher( &data->threefish_data,
					     data->buffer,
					     data->keystream );
			{
				uint64_t temp;
				std::memcpy( &temp, data->keystream, sizeof(temp) );
				++temp;
				std::memcpy( data->keystream, &temp, sizeof(temp) );
			}
			SSC_XOR (data->buffer, input, Block_Bytes);
			std::memcpy( output, data->buffer, Block_Bytes );
			input      += Block_Bytes;
			output     += Block_Bytes;
			input_size -= Block_Bytes;
		}
		if( input_size > 0 ) {
			Threefish_f::cipher( &data->threefish_data,
					     data->buffer,
					     data->keystream );
			for( uint64_t i = 0; i < input_size; ++i )
				data->buffer[ i ] ^= input[ i ];
			std::memcpy( output, data->buffer, input_size );
		}
	}
}// ~ namespace ssc
#undef CLASS
#undef TEMPLATE_ARGS
