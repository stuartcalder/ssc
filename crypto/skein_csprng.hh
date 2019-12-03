/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once
#include <cstdlib>
#include <cstring>
#include <climits>
#include <memory>
#include <utility>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/error_conditions.hh>

#ifdef TEST
#	error "Already defined"
#endif

#ifdef __SSC_ENABLE_TESTING
#	define TEST true
#else
#	define TEST false
#endif

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error "Already defined"
#endif
namespace ssc {
        template <int State_Bits>
        class Skein_CSPRNG {
        public:
		static_assert	 (CHAR_BIT == 8);
		static_assert	 (State_Bits == 256 || State_Bits == 512 || State_Bits == 1024);
		using Skein_t =  Skein<State_Bits>;
		CTIME_CONST(bool)	Do_Runtime_Checks = TEST;
		CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;

		Skein_CSPRNG (Skein_t *__restrict sk, u8_t *__restrict buf, u64_t size)
			: skein{ sk }, buffer{ buf }, buffer_size{ size }
		{
			if constexpr(Do_Runtime_Checks)
				if (buffer_size < (State_Bytes * 2))
					errx( "buffer_size must be at least State_Bytes * 2 in Skein_CSPRNG\n" );
		}
#if 0
                Skein_CSPRNG (void);

                Skein_CSPRNG (void const * const seed,
                              u64_t const        seed_bytes);

		~Skein_CSPRNG (void);
		Skein_CSPRNG (void) = delete;

		Skein_CSPRNG (Threefish_t *__restrict threefish,
		Skein_CSPRNG (u8_t *__restrict buffer);

		Skein_CSPRNG (u8_t *__restrict   buffer,
			      void const * const seed,
			      u64_t const        seed_bytes);
#endif
		
                /* void reseed(seed,seed_bytes)
                 *      Copies in ${seed_bytes} bytes into the state, and
                 *      hashes them. */
		void
		reseed (void const * const seed);
#if 0
                void
                reseed (void const * const seed,
                        u64_t const        seed_bytes);
#endif

                /* void os_reseed(seed_bytes)
                 *      Reseeds the state using ${seed_bytes} bytes of entropy
                 *      received from the operating system. */
		void
		os_reseed (void);
#if 0
                void
                os_reseed (u64_t const seed_bytes = State_Bytes);
#endif

                /* void get(output_buffer,requested_bytes)
                 *      Writes ${requested_bytes} pseudorandom bytes into the ${output_buffer}. */
                void
                get (void * const output_buffer,
                     u64_t const  requested_bytes);
        private:
#if 0
		u8_t	state [State_Bytes];
                Skein_t	skein;
#endif
		Skein_t *skein;
		u8_t	*buffer;
		u64_t	buffer_size;

        }; /* ! class Skein_CSPRNG */

#if 0
        template<int State_Bits>
        Skein_CSPRNG<State_Bits>::Skein_CSPRNG (void)
	{
#ifdef __SSC_MemoryLocking__
		lock_os_memory( state, sizeof(state) );
#endif
		obtain_os_entropy( state, sizeof(state) );
        } /* Skein_CSPRNG (void) */

        template <int State_Bits>
        Skein_CSPRNG<State_Bits>::Skein_CSPRNG (void const * const seed,
		                                u64_t const        seed_bytes)
	{
#ifdef __SSC_MemoryLocking__
		lock_os_memory( state, sizeof(state) );
#endif
		std::memset( state, 0, sizeof(state) );
		this->reseed( seed, seed_bytes );
	}

	template <int State_Bits>
	Skein_CSPRNG<State_Bits>::~Skein_CSPRNG (void)
	{
		zero_sensitive( state, sizeof(state) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( state, sizeof(state) );
#endif
	}
#endif

        template <int State_Bits>
        void
#if 0
        Skein_CSPRNG<State_Bits>::reseed (void const * const seed,
                                          u64_t const        seed_bytes)
#endif
	Skein_CSPRNG<State_Bits>::reseed (void const * const seed) {
		using std::memcpy;

		u8_t	*state   = buffer;
		u8_t	*scratch = buffer + State_Bytes;

		memcpy( scratch                , state, State_Bytes );
		memcpy( (scratch + State_Bytes), seed , State_Bytes );
		
		static_assert	(Skein_t::State_Bytes == State_Bytes);
		skein->hash_native( state, scratch, (State_Bytes * 2) );
#if 0
		using std::memcpy;
		u64_t const buffer_size = seed_bytes + sizeof(state);
		auto buffer = std::make_unique<u8_t []>( buffer_size );
#ifdef __SSC_MemoryLocking__
		bool const is_lockable = seed_bytes <= Max_Lockable_Bytes;
		if (is_lockable)
			lock_os_memory( buffer.get(), buffer_size );
#endif

		memcpy( buffer.get()                  , state, sizeof(state) );
		memcpy( (buffer.get() + sizeof(state)), seed , seed_bytes    );

		static_assert (Skein_t::State_Bytes == sizeof(state));
		skein.hash_native( state, buffer.get(), buffer_size );

		zero_sensitive( buffer.get(), buffer_size );
#ifdef __SSC_MemoryLocking__
		if (is_lockable)
			unlock_os_memory( buffer.get(), buffer_size );
#endif
#endif
        } /* reseed (u8_t *,u64_t) */

        template <int State_Bits>
        void
        Skein_CSPRNG<State_Bits>::os_reseed (void) {
		using std::memcpy;

		u8_t	*state   = buffer;
		u8_t	*scratch = buffer + State_Bytes;

		memcpy( scratch, state, State_Bytes );
		obtain_os_entropy( (scratch + State_Bytes), State_Bytes );
		static_assert	(Skein_t::State_Bytes == State_Bytes);
		skein->hash_native( state, scratch, (State_Bytes * 2) );
#if 0
		u64_t const buffer_size = seed_bytes + sizeof(state);
		auto buffer = std::make_unique<u8_t []>( buffer_size );
#ifdef __SSC_MemoryLocking__
		bool const is_lockable = buffer_size <= Max_Lockable_Bytes;
		if (is_lockable)
			lock_os_memory( buffer.get(), buffer_size );
#endif

		memcpy( buffer.get(), state, sizeof(state) );
		obtain_os_entropy( (buffer.get() + sizeof(state)), seed_bytes );

		static_assert (Skein_t::State_Bytes == sizeof(state));
		skein.hash_native( state, buffer.get(), buffer_size );
		zero_sensitive( buffer.get(), buffer_size );
#ifdef __SSC_MemoryLocking__
		if (is_lockable)
			unlock_os_memory( buffer.get(), buffer_size );
#endif
#endif
        } /* os_reseed (u64_t) */

        template <int State_Bits>
        void
        Skein_CSPRNG<State_Bits>::get (void * const output_buffer,
                                       u64_t const  requested_bytes) {
		using std::memcpy;
		
		if constexpr(Do_Runtime_Checks)
			if (buffer_size < (requested_bytes + State_Bytes))
				errx( "Buffer not big enough in Skein_CSPRNG::get()\n" );

		u8_t	*state   = buffer;
		u8_t	*scratch = buffer + State_Bytes;

		skein->hash( scratch, state, State_Bytes, (requested_bytes + State_Bytes) );
		memcpy( state        , scratch                , State_Bytes     );
		memcpy( output_buffer, (scratch + State_Bytes), requested_bytes );
#if 0
		using std::memcpy;
		u64_t const buffer_size = requested_bytes + sizeof(state);
		auto buffer = std::make_unique<u8_t []>( buffer_size );
#ifdef __SSC_MemoryLocking__
		bool is_lockable = buffer_size <= Max_Lockable_Bytes;
		if (is_lockable)
			lock_os_memory( buffer.get(), buffer_size );
#endif
		skein.hash( buffer.get(), state, sizeof(state), buffer_size );
		memcpy( state, buffer.get(), sizeof(state) );
		memcpy( output_buffer, (buffer.get() + sizeof(state)), requested_bytes );
		zero_sensitive( buffer.get(), buffer_size );
#ifdef __SSC_MemoryLocking__
		if (is_lockable)
			unlock_os_memory( buffer.get(), buffer_size );
#endif
#endif
        } /* get (u8_t *,u64_t) */
}/* ! namespace ssc */
#undef CTIME_CONST
#undef TEST
