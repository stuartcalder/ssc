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
#include <ssc/crypto/sspkdf.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#ifdef __SSC_ENABLE_EXPERIMENTAL
#	include <ssc/crypto/sensitive_buffer.hh>
#endif
#include <ssc/general/integers.hh>
#include <ssc/memory/os_memory_locking.hh>

namespace ssc
{
	static_assert (CHAR_BIT == 8);
	void
	sspkdf	(u8_t *__restrict const derived_key,
		 char const *__restrict password,
		 int const              password_length,
		 u8_t const *__restrict salt,
		 u32_t const            number_iterations,
		 u32_t const            number_concatenations) {
	using std::memcpy, std::make_unique;
	static constexpr auto const State_Bits = 512;
	static constexpr auto const State_Bytes = State_Bits / CHAR_BIT;
	static constexpr auto const Salt_Bits = 128;
	static constexpr auto const Salt_Bytes = Salt_Bits / CHAR_BIT;
	using Skein_t = Skein<State_Bits>;
	Skein_t skein;
	using Index_t = u32_t;
	u64_t const concat_size = (static_cast<u64_t>(password_length) + Salt_Bytes + sizeof(Index_t)) * static_cast<u64_t>(number_concatenations);
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
#ifdef __SSC_ENABLE_EXPERIMENTAL
		Sensitive_Buffer<u8_t, State_Bytes> key;
		Sensitive_Buffer<u8_t, State_Bytes> buffer;
#else
		u8_t	key	[State_Bytes];
		u8_t	buffer	[State_Bytes];

#	ifdef __SSC_MemoryLocking__
		lock_os_memory( key   , sizeof(key)   );
		lock_os_memory( buffer, sizeof(buffer) );
#	endif
#endif

#ifdef __SSC_ENABLE_EXPERIMENTAL
		if constexpr(skein.State_Bytes == State_Bytes)
			skein.hash_native( key.get(), concat_buffer.get(), concat_size );
		else
			skein.hash( key.get(), concat_buffer.get(), concat_size, key.Num_Bytes );
#else
		if constexpr(Skein_t::State_Bytes == State_Bytes)
			skein.hash_native( key, concat_buffer.get(), concat_size );
		else
			skein.hash( key, concat_buffer.get(), concat_size, sizeof(key) );
#endif
#ifdef __SSC_ENABLE_EXPERIMENTAL
		skein.message_auth_code( buffer.get(), concat_buffer.get(), key.get(), concat_size, key.Num_Bytes, buffer.Num_Bytes );
#else
		skein.message_auth_code( buffer, concat_buffer.get(), key, concat_size, sizeof(key), sizeof(buffer) );
#endif
		zero_sensitive( concat_buffer.get(), concat_size );
#ifdef __SSC_ENABLE_EXPERIMENTAL
		xor_block<State_Bits>( key.get(), buffer.get() );
#else
		xor_block<State_Bits>( key, buffer );
#endif

		for (u32_t i = 1; i < number_iterations; ++i) {
#ifdef __SSC_ENABLE_EXPERIMENTAL
			skein.message_auth_code( buffer.get(), buffer.get(), key.get(), buffer.Num_Bytes, key.Num_Bytes, buffer.Num_Bytes );
			xor_block<State_Bits>( key.get(), buffer.get() );
#else
			skein.message_auth_code( buffer, buffer, key, sizeof(buffer), sizeof(key), sizeof(buffer) );
			xor_block<State_Bits>( key, buffer );
#endif
		}
		static_assert (Skein_t::State_Bytes == State_Bytes);
#ifdef __SSC_ENABLE_EXPERIMENTAL
		skein.hash_native( derived_key, buffer.get(), buffer.Num_Bytes );
#else
		skein.hash_native( derived_key, buffer, sizeof(buffer) );

		zero_sensitive( key   , sizeof(key)    );
		zero_sensitive( buffer, sizeof(buffer) );
#	ifdef __SSC_MemoryLocking__
		unlock_os_memory( key   , sizeof(key)    );
		unlock_os_memory( buffer, sizeof(buffer) );
#	endif
#endif
	}
    } /* sspkdf */
} /* ! namespace ssc */
