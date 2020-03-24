/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <utility>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
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

#ifdef TEMPLATE_ARGS
#	error 'TEMPLATE_ARGS Already Defined'
#else
#	define TEMPLATE_ARGS template <typename Block_Cipher_t,int Block_Bits>
#endif

#ifdef CLASS
#	error 'CLASS Already Defined'
#else
#	define CLASS Cipher_Block_Chaining<Block_Cipher_t,Block_Bits>
#endif

namespace ssc
{
	TEMPLATE_ARGS
	class Cipher_Block_Chaining
	{
	public:
		/* COMPILE TIME CHECKS */
		static_assert (CHAR_BIT == 8);
		static_assert (Block_Bits % CHAR_BIT == 0);
		static_assert (Block_Bits >= 128);
		static_assert (Block_Cipher_t::Block_Bits == Block_Bits);
		/* COMPILE TIME CONSTANTS */
		_CTIME_CONST(int) Block_Bytes   = Block_Bits / CHAR_BIT;
		_CTIME_CONST(int) State_Bytes   = Block_Bytes;
		_CTIME_CONST(int) Scratch_Bytes = Block_Bytes * 2;
		_CTIME_CONST(int) Buffer_Bytes  = State_Bytes + Scratch_Bytes;
		/* PUBLIC INTERFACE */
		Cipher_Block_Chaining (void) = delete;
		Cipher_Block_Chaining (Block_Cipher_t *__restrict cipher, u8_t *__restrict buffer)
			: blk_cipher{ cipher }, state{ buffer }, scratch{ buffer + State_Bytes }
		{
		} /* ~ Cipher_Block_Chaining (Block_Cipher_t*,u8_t*) */
		size_t	encrypt (u8_t *__restrict bytes_out, u8_t const *__restrict bytes_in, size_t const size_in, u8_t const *__restrict iv);
		size_t	decrypt	(u8_t *__restrict bytes_out, u8_t const *__restrict bytes_in, size_t const size_in, u8_t const *__restrict iv);
	private:
		/* PRIVATE STATE */
		Block_Cipher_t	*blk_cipher;
		u8_t		*state;
		u8_t		*scratch;
		/* PRIVATE INTERFACE */

		static size_t count_iso_iec_7816_padding_bytes_ (u8_t const * const bytes, size_t const padded_size);
		static size_t calculate_padded_ciphertext_size_ (size_t const unpadded_plaintext_size);
	}; /* Cipher_Block_Chaining */
	/* Constructors */

	TEMPLATE_ARGS
	size_t CLASS::count_iso_iec_7816_padding_bytes_ (u8_t const * const bytes, size_t const padded_size)
	{
		using namespace std;
		size_t i = padded_size - 1, count = 0;
		for (; i <= padded_size; --i) {
			++count;
			if (bytes[ i ] == 0x80)
				return count;
		}
		errx( "Error: Invalid Cipher_Block_Chaining padding\n" );
		return 1; // This should be unreachable, but will supress warnings about return values.
	} /* ~ count_iso_iec_7816_padding_bytes_(u8_t*,size_t) */

	TEMPLATE_ARGS
	size_t CLASS::calculate_padded_ciphertext_size_ (size_t const unpadded_plaintext_size)
	{
		return unpadded_plaintext_size + (Block_Bytes - (unpadded_plaintext_size % Block_Bytes));
	} /* ~ calculate_padded_ciphertext_size_(size_t) */

	TEMPLATE_ARGS
	size_t CLASS::encrypt (u8_t *bytes_out, u8_t const *bytes_in, size_t const size_in, u8_t const * __restrict iv)
	{
		using std::memcpy;
		if (iv != nullptr)
			memcpy( state, iv, State_Bytes );
		u8_t const	*in  = bytes_in;
		u8_t		*out = bytes_out;
		size_t		bytes_left = size_in;

		while (bytes_left >= Block_Bytes) {
			memcpy( scratch, in, Block_Bytes );
			xor_block<Block_Bits>( scratch, state );
			blk_cipher->cipher( state, scratch );
			memcpy( out, state, Block_Bytes );

			in         += Block_Bytes;
			out        += Block_Bytes;
			bytes_left -= Block_Bytes;
		}
		memcpy( scratch, in, bytes_left );
		scratch[ bytes_left ] = 0x80;
		memset( (scratch + bytes_left + 1), 0, ((Block_Bytes - 1) - bytes_left) );
		// Final encrypt
		xor_block<Block_Bits>( scratch, state );
		blk_cipher->cipher( state, scratch );
		memcpy( out, state, Block_Bytes );

		return calculate_padded_ciphertext_size_( size_in );
	} /* ~ encrypt(u8_t*,u8_t const*,size_t const, u8_t const*) */

	TEMPLATE_ARGS
	size_t CLASS::decrypt (u8_t *bytes_out, u8_t const *bytes_in, size_t const size_in, u8_t const *__restrict iv)
	{
		using std::memcpy;

		if (iv != nullptr)
			memcpy( state, iv, State_Bytes );
		size_t const last_block_offset = ((size_in >= Block_Bytes) ? (size_in - Block_Bytes) : 0);

		u8_t * const ciphertext = scratch;
		u8_t * const buffer     = scratch + Block_Bytes;

		for (size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes) {
			u8_t const	*block_in  = bytes_in  + b_off;
			u8_t		*block_out = bytes_out + b_off;
			memcpy( ciphertext, block_in, Block_Bytes );
			blk_cipher->inverse_cipher( buffer, ciphertext );
			xor_block<Block_Bits>( buffer, state );
			memcpy( block_out, buffer    , Block_Bytes );
			memcpy( state    , ciphertext, Block_Bytes );
		}

		return size_in - count_iso_iec_7816_padding_bytes_( bytes_out, size_in );
	} /* ~ decrypt(u8_t*,u8_t const*,size_t const,u8_t const*) */
}/* namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
