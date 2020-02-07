/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
			u8_t	key	[State_Bytes];
			u8_t	buffer	[State_Bytes];

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
} /* ! namespace ssc::crypto_impl */
