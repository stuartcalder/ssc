/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#include <cstdlib>
#include <climits>
#include <ssc/crypto/skein_f.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/memory/os_memory_locking.hh>

#include "sspkdf.hh"

namespace ssc::crypto_impl {
	static_assert (CHAR_BIT == 8);
	void sspkdf (typename UBI_f::Data     *ubi_data,
		     _RESTRICT (u8_t *)	      output,
		     _RESTRICT (u8_t const *) password,
		     int const		      password_size,
		     _RESTRICT (u8_t const *) salt,
		     u32_t const	      num_iter,
		     u32_t const	      num_concat)
	{
		_CTIME_CONST (int) State_Bits  = 512;
		_CTIME_CONST (int) State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST (int) Salt_Bits   = 128;
		_CTIME_CONST (int) Salt_Bytes  = Salt_Bits / CHAR_BIT;

		u64_t const concat_size = (static_cast<u64_t>(password_size) + Salt_Bytes + sizeof(u32_t)) * static_cast<u64_t>(num_concat);
		u8_t * const concat_buffer = static_cast<u8_t*>(std::malloc( concat_size ));
		if( concat_buffer == nullptr )
			errx( "Error: SSPKDF failed to malloc\n" );
		{
			u32_t index = 0;
			u8_t *buf_ptr = concat_buffer;
			u8_t * const buf_end = buf_ptr + concat_size;
			while( buf_ptr < buf_end ) {
				std::memcpy( buf_ptr, password, password_size);
				buf_ptr += password_size;
				std::memcpy( buf_ptr, salt, Salt_Bytes );
				buf_ptr += Salt_Bytes;
				*(reinterpret_cast<u32_t*>(buf_ptr)) = index;
				buf_ptr += sizeof(index);
				++index;
			}
		}
		{
			alignas(u64_t) u8_t key    [Block_Bytes];
			alignas(u64_t) u8_t buffer [Block_Bytes];

			Skein_f::hash_native( ubi_data, key, concat_buffer, concat_size );
			Skein_f::mac( ubi_data, buffer, concat_buffer, key, sizeof(buffer), concat_size );
			zero_sensitive( concat_buffer, concat_size );
			std::free( concat_buffer );
			xor_block<State_Bits>( key, buffer );

			for (u32_t i = 1; i < num_iter; ++i) {
				Skein_f::mac( ubi_data, buffer, buffer, key, sizeof(buffer), sizeof(buffer) );
				xor_block<State_Bits>( key, buffer );
			}
			Skein_f::hash_native( ubi_data, output, buffer, sizeof(buffer) );
			zero_sensitive( key   , sizeof(key)    );
			zero_sensitive( buffer, sizeof(buffer) );
		}
	}
} /* ! namespace ssc::crypto_impl */
