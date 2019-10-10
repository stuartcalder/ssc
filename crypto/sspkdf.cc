/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <ssc/crypto/sspkdf.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/memory/os_memory_locking.hh>

namespace ssc
{
	void
	sspkdf	(u8_t *__restrict const derived_key,
		 char const *__restrict password,
		 int const              password_length,
		 u8_t const *__restrict salt,
		 u32_t const            number_iterations,
		 u32_t const            number_concatenations) {
	using std::memcpy;
	static constexpr auto const State_Bits = 512;
	static constexpr auto const State_Bytes = State_Bits / 8;
	static constexpr auto const Salt_Bits = 128;
	static constexpr auto const Salt_Bytes = Salt_Bits / 8;
	Skein<State_Bits> skein;
	using Index_t = u32_t;
	u64_t const concat_size = (static_cast<u64_t>(password_length) + Salt_Bytes + sizeof(Index_t)) * number_concatenations;
	auto concat_buffer = std::make_unique<u8_t[]>( concat_size );

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
		u8_t key    [State_Bytes];
		u8_t buffer [State_Bytes];
#ifdef __SSC_memlocking__
		lock_os_memory( key   , sizeof(key)    );
		lock_os_memory( buffer, sizeof(buffer) );
#endif

		skein.hash( key, concat_buffer.get(), concat_size, sizeof(key) );
		skein.message_auth_code( buffer, concat_buffer.get(), key, concat_size, sizeof(key), sizeof(buffer) );
		xor_block<State_Bits>( key, buffer );
		for (u32_t i = 1; i < number_iterations; ++i) {
			skein.message_auth_code( buffer, buffer, key, sizeof(buffer), sizeof(key), sizeof(buffer) );
			xor_block<State_Bits>( key, buffer );
		}
		skein.hash( derived_key, buffer, sizeof(buffer), State_Bytes );
		zero_sensitive( key   , sizeof(key) );
		zero_sensitive( buffer, sizeof(buffer) );
#ifdef __SSC_memlocking__
		unlock_os_memory( key, sizeof(key) );
		unlock_os_memory( buffer, sizeof(buffer) );
#endif
	}
	zero_sensitive( concat_buffer.get(), concat_size );
    } /* sspkdf */
} /* ! namespace ssc */
