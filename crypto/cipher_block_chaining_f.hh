#pragma once
#include <ssc/general/macros.hh>
#include <ssc/crypto/threefish_f.hh>

#if    defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'Some MACRO we need was already defined'
#endif

#define TEMPLATE_ARGS	template <int Bits>
#define CLASS		Cipher_Block_Chaining_F<Bits>

namespace ssc
{
	TEMPLATE_ARGS
	class Cipher_Block_Chaining_F
	{
	public:
		static_assert (CHAR_BIT == 8);
		static_assert (Bits % CHAR_BIT == 0);
		static_assert (Bits == 256 || Bits == 512 || Bits == 1024);
		using Threefish_f = Threefish_F<Bits,Key_Schedule_E::Pre_Compute>;

		_CTIME_CONST (int) Block_Bits = Bits;
		_CTIME_CONST (int) Block_Bytes = Block_Bits / CHAR_BIT;

		Cipher_Block_Chaining_F (void) = delete;

		struct Data {
			typename Threefish_f::Data_t threefish_data;
			alignas(u64_t)          u8_t state [Block_Bytes];
			alignas(u64_t)          u8_t temp  [Block_Bytes];
		};

		static inline size_t padded_ciphertext_size (size_t const unpadded_plaintext_size);
		static int           count_iso_iec_7816_padding_bytes (_RESTRICT (u8_t const *) last_block);

		static size_t encrypt (_RESTRICT (Data *)       data,
				       _RESTRICT (u8_t *)       out_bytes,
				       _RESTRICT (u8_t const *) in_bytes,
				       _RESTRICT (u8_t const *) init_vec,
				       size_t                   num_bytes_in);

		static size_t decrypt (_RESTRICT (Data *)       data,
				       _RESTRICT (u8_t *)       out_bytes,
				       _RESTRICT (u8_t const *) in_bytes,
				       _RESTRICT (u8_t const *) init_vec,
				       size_t const             num_bytes_in);
	};

	TEMPLATE_ARGS
	size_t CLASS::padded_ciphertext_size (size_t const unpadded_plaintext_size)
	{
		return unpadded_plaintext_size + (Block_Bytes - (unpadded_plaintext_size % Block_Bytes));
	} 

	TEMPLATE_ARGS
	int CLASS::count_iso_iec_7816_padding_bytes (_RESTRICT (u8_t const *) last_block)
	{
		int count = 1;
		u8_t mask = 0x00;
		static_assert (CHAR_BIT == 8);
		for( int i = Block_Bytes - 1; i >= 0; --i ) {
			mask |= static_cast<u8_t>(static_cast<i8_t>(bytes[ i ]) >> (CHAR_BIT - 1));
			count += (mask & 0b0000'0001);
		}
		return count;
	}

	TEMPLATE_ARGS
	size_t CLASS::encrypt (_RESTRICT (Data *)       data,
		               _RESTRICT (u8_t *)       out_bytes,
			       _RESTRICT (u8_t const *) in_bytes,
			       _RESTRICT (u8_t const *) init_vec,
			       size_t                   num_bytes_in)
	{
		using std::memcpy;
		memcpy( data->state, init_vec, Block_Bytes );
		while( num_bytes_in >= Block_Bytes ) {
			memcpy( data->temp, in_bytes, Block_Bytes );
			xor_block<Block_Bits>( data->temp, data->state );
			memcpy( out_bytes, state, Block_Bytes );
			in_bytes     += Block_Bytes;
			out_bytes    += Block_Bytes;
			num_bytes_in -= Block_Bytes;
		}
		memcpy( data->temp, in_bytes, bytes_left );
		data->temp[ bytes_left ] = 0x80;
		memset( (data->temp + bytes_left + 1), 0, ((Block_Bytes - 1) - bytes_left) );
		xor_block<Block_Bits>( data->temp, data->state );
		Threefish_f::cipher( &(data->threefish_data), data->state, data->temp );
		memcpy( out_bytes, data->state, Block_Bytes );
		return padded_ciphertext_size( bytes_left );
	}

	TEMPLATE_ARGS
	size_t CLASS::decrypt (_RESTRICT (Data *)       data,
		               _RESTRICT (u8_t *)       out_bytes,
			       _RESTRICT (u8_t const *) in_bytes,
			       _RESTRICT (u8_t const *) init_vec,
			       size_t                   num_bytes_in)
	{
		using std::memcpy;
		memcpy( data->state, init_vec, Block_Bytes );
		size_t bytes_left = num_bytes_in;
		while( bytes_left >= Block_Bytes ) {
			Threefish_f::inverse_cipher( &(data->threefish_data), data->temp, in_bytes );
			xor_block<Block_Bits>( data->temp, data->state );
			memcpy( out_bytes, data->temp, Block_Bytes );
			memcpy( data->state, in_bytes, Block_Bytes );
			in_bytes += Block_Bytes;
			out_bytes += Block_Bytes;
			bytes_left -= Block_Bytes;
		}
		return num_bytes_in - count_iso_iec_7816_padding_bytes( in_bytes - Block_Bytes );
	}
}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
