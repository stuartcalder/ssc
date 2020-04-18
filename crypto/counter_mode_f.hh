#pragma once
/* SSC General Headers */
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/error_conditions.hh>
/* SSC Crypto Headers */
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish_f.hh>
/* C Standard Headers */
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>
/* C++ Standard Headers */
#include <utility>

#if    defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'Some MACRO needed was already defined!'
#endif
#define TEMPLATE_ARGS	template <typename Block_Bits>
#define CLASS		Counter_Mode_F<Block_Bits>

namespace ssc
{
	TEMPLATE_ARGS
	class Counter_Mode_F
	{
	public:
		static_assert (CHAR_BIT == 8);
		static_assert (Block_Bits % CHAR_BIT == 0);
		static_assert (Block_Bits >= 128, "Modern block ciphers have blocks of at least 128 bits.");
		_CTIME_CONST (int) Block_Bytes = Block_Bits / CHAR_BIT;
		static_assert (Block_Bytes % 2 == 0, "Block bytes must be evenly divisible in half.");
		_CTIME_CONST (int) Nonce_Bytes = Block_Bytes / 2;
		using Threefish_f = Threefish_F<Block_Bits,Key_Schedule_E::Pre_Compute>;
		using Threefish_Data_t = typename Threefish_f::Data_t;
		struct Data {
			Threefish_Data_t    threefish_data;
			alignas(u64_t) u8_t keystream [Block_Bytes];
			alignas(u64_t) u8_t buffer    [Block_Bytes];
		};

		Counter_Mode_F (void) = delete;

		inline void set_nonce (_RESTRICT (Data       *) data,
				       _RESTRICT (u8_t const *) nonce);
		void xorcrypt (_RESTRICT (Data *) data,
			       u8_t               *output,
			       u8_t const         *input,
			       u64_t              input_size,
			       u64_t              starting_byte = 0);
	};

	TEMPLATE_ARGS
	void CLASS::set_nonce (_RESTRICT (Data       *) data,
			       _RESTRICT (u8_t const *) nonce)
	{
		static_assert (Block_Bytes == (Nonce_Bytes * 2));
		static_assert (sizeof(u64_t) <= Nonce_Bytes);
		if constexpr (sizeof(u64_t) != Nonce_Bytes)
			std::memset( (data->keystream + sizeof(u64_t)), 0, (Nonce_Bytes - sizeof(u64_t)) );
		std::memcpy( (data->keystream + Nonce_Bytes),
			     nonce,
			     Nonce_Bytes );
	}

	TEMPLATE_ARGS
	void CLASS::xorcrypt (_RESTRICT (Data *) data,
			      u8_t               *output,
			      u8_t               *input,
			      u64_t              input_size,
			      u64_t              starting_byte)
	{
		if( starting_byte == 0 ) {
			*(reinterpret_cast<u64_t*>(data->keystream)) = starting_byte;
		} else {
			u64_t starting_block = starting_byte / Block_Bytes;
			u64_t offset         = starting_byte % Block_Bytes;
			u64_t bytes          = Block_Bytes - offset;
			*(reinterpret_cast<u64_t*>(data->keystream)) = starting_block;
			Threefish_f::cipher( &(data->threefish_data),
					     data->buffer,
					     data->keystream );
			++(*reinterpret_cast<u64_t*>(data->keystream));
			u8_t const *offset_buffer = data->buffer + offset;
			u64_t left;
			if( input_size >= bytes )
				left = bytes;
			else
				left = input_size;
			for( int i = 0; i < left; ++i )
				offset_buffer[ i ] ^= input[ i ];
			std::memcpy( output, offset_buffer, left );
			input      += left;
			output     += left;
			input_size -= left;
		}
		while( input_size >= Block_Bytes ) {
			Threefish_f::cipher( &(data->threefish_data),
					     data->buffer,
					     data->keystream );
			++(*reinterpret_cast<u64_t*>(data->keystream));
			xor_block<Block_Bits>( data->buffer, input );
			std::memcpy( output, data->buffer, Block_Bytes );
			input      += Block_Bytes;
			output     += Block_Bytes;
			input_size -= Block_Bytes;
		}
		if( input_size > 0 ) {
			Threefish_f::cipher( &(data->threefish_data),
					     data->buffer,
					     data->keystream );
			for( int i = 0; i < input_size; ++i )
				data->buffer[ i ] ^= input[ i ];
			std::memcpy( output, data->buffer, input_size );
		}
	}
}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
