/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#include <cstdlib>
#include <climits>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/memory/os_memory_locking.hh>

#include "sspkdf.hh"

namespace ssc::crypto_impl {
	static_assert (CHAR_BIT == 8);
	void sspkdf (_RESTRICT (typename UBI_f::Data *) ubi_data,
		     _RESTRICT (u8_t *)		        output,
		     _RESTRICT (u8_t const *)	        password,
		     int const			        password_size,
		     _RESTRICT (u8_t const *)	        salt,
		     u32_t const		        num_iter,
		     u32_t const		        num_concat)
	{
		_CTIME_CONST (int) State_Bits  = 512;
		_CTIME_CONST (int) State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST (int) Salt_Bits   = 128;
		_CTIME_CONST (int) Salt_Bytes  = Salt_Bits / CHAR_BIT;

		u64_t const concat_size = (static_cast<u64_t>(password_length) + Salt_Bytes + sizeof(u32_t)) * static_cast<u64_t>(num_concat);
		auto concat_buffer = std::make_unique<u8_t[]>( concat_size );
		{
			u32_t index = 0;
			u8_t *buf_ptr = concat_buffer.get();
			u8_t * const buf_end = buf_ptr + concat_size;
			while( buf_ptr < buf_end ) {
				std::memcpy( buf_ptr, password, password_length );
				buf_ptr += password_length;
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

			Skein_f::hash_native( ubi_data, key, concat_buffer.get(), concat_size );
			Skein_f::mac( ubi_data, buffer, concat_buffer.get(), key, sizeof(buffer), concat_size );
			zero_sensitive( concat_buffer.get(), concat_size );
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
#if 0
	void
	sspkdf (u8_t *output,
		Skein_t &skein,
		char const *password,
		int  const password_length,
		u8_t const *salt,
		u32_t const num_iter,
		u32_t const num_concat)
	{
		using std::memcpy, std::make_unique;

		_CTIME_CONST(int)	State_Bits  = 512;
		_CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST(int)	Salt_Bits   = 128;
		_CTIME_CONST(int)	Salt_Bytes  = Salt_Bits / CHAR_BIT;

		using Index_t = u32_t;
		u64_t const concat_size = (static_cast<u64_t>(password_length) + Salt_Bytes + sizeof(Index_t)) * static_cast<u64_t>(num_concat);
		auto concat_buffer = make_unique<u8_t []>( concat_size );

		{
			Index_t index = 0;
			auto buf_ptr = concat_buffer.get();
			auto const buf_end = buf_ptr + concat_size;
			while (buf_ptr < buf_end) {
				memcpy( buf_ptr, password, password_length );
				buf_ptr += password_length;
				memcpy( buf_ptr, salt, Salt_Bytes );
				buf_ptr += Salt_Bytes;
				memcpy( buf_ptr, &index, sizeof(index) );
				buf_ptr += sizeof(index);
				++index;
			}
		}
		{
			alignas(u64_t) u8_t key	   [State_Bytes];
			alignas(u64_t) u8_t buffer [State_Bytes];

			skein.hash_native( key, concat_buffer.get(), concat_size );
			skein.message_auth_code( buffer, concat_buffer.get(), key, concat_size, sizeof(key), sizeof(buffer) );
			zero_sensitive( concat_buffer.get(), concat_size );
			xor_block<State_Bits>( key, buffer );

			for (u32_t i = 1; i < num_iter; ++i) {
				skein.message_auth_code( buffer, buffer, key, sizeof(buffer), sizeof(key), sizeof(buffer) );
				xor_block<State_Bits>( key, buffer );
			}
			skein.hash_native( output, buffer, sizeof(buffer) );

			zero_sensitive( key   , sizeof(key)    );
			zero_sensitive( buffer, sizeof(buffer) );
		}
	}
#endif
} /* ! namespace ssc::crypto_impl */
