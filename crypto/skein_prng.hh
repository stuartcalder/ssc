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
#include <ssc/crypto/sensitive_buffer.hh>
#include <ssc/crypto/sensitive_dynamic_buffer.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>
#include <ssc/memory/os_memory_locking.hh>

namespace ssc {
        template <size_t State_Bits>
        class Skein_PRNG {
        public:
                static_assert (State_Bits == 256 ||
                               State_Bits == 512 ||
                               State_Bits == 1024,
                               "Skein_PRNG only defined for state sizes of 256,512,1024 bits");
		static_assert (CHAR_BIT == 8);
                static constexpr size_t const State_Bytes = State_Bits / CHAR_BIT;
		static constexpr size_t const Max_Lockable_Bytes = 256;
                using Skein_t = Skein<State_Bits>;

                Skein_PRNG (void);

                Skein_PRNG (void const * const seed,
                            u64_t const        seed_bytes);

                /* void reseed(seed,seed_bytes)
                 *      Copies in ${seed_bytes} bytes into the state, and
                 *      hashes them. */
                void
                reseed (void const * const seed,
                        u64_t const        seed_bytes);

                /* void os_reseed(seed_bytes)
                 *      Reseeds the state using ${seed_bytes} bytes of entropy
                 *      received from the operating system. */
                void
                os_reseed (u64_t const seed_bytes = State_Bytes);

                /* void get(output_buffer,requested_bytes)
                 *      Writes ${requested_bytes} pseudorandom bytes into the ${output_buffer}. */
                void
                get (void * const output_buffer,
                     u64_t const  requested_bytes);
        private:
		Sensitive_Buffer<u8_t, State_Bytes>	state;
                Skein_t					skein;

		static inline bool
		is_lockable_ (size_t const);
        }; /* ! class Skein_PRNG */

        template<size_t State_Bits>
        Skein_PRNG<State_Bits>::Skein_PRNG (void)
	{
		obtain_os_entropy( state.get(), state.size() );
        } /* Skein_PRNG (void) */

        template <size_t State_Bits>
        Skein_PRNG<State_Bits>::Skein_PRNG (void const * const seed,
                                            u64_t const        seed_bytes)
		: state{ 0 }
	{
		reseed( seed, seed_bytes );
        } /* Skein_PRNG (u8_t*,u64_t) */

        template <size_t State_Bits>
        void
        Skein_PRNG<State_Bits>::reseed (void const * const seed,
                                        u64_t const        seed_bytes) {
		using std::memcpy;
		u64_t const buffer_size = seed_bytes + state.size();
		Sensitive_Dynamic_Buffer<u8_t> buffer{ buffer_size, is_lockable_( buffer_size ) };

		memcpy( buffer.get()                 , state.get(), state.size() );
		memcpy( (buffer.get() + state.size()), seed       , seed_bytes   );

		static_assert (Skein_t::State_Bytes == decltype(state)::Num_Bytes);
		skein.hash_native( state.get(), buffer.get(), buffer_size );
        } /* reseed (u8_t*,u64_t) */

        template <size_t State_Bits>
        void
        Skein_PRNG<State_Bits>::os_reseed (u64_t const seed_bytes) {
		using std::memcpy;
		u64_t const buffer_size = seed_bytes + state.size();
		Sensitive_Dynamic_Buffer<u8_t> buffer{ buffer_size, is_lockable_( buffer_size ) };

		memcpy( buffer.get(), state.get(), state.size() );
		obtain_os_entropy( (buffer.get() + state.size()), seed_bytes );

		static_assert (Skein_t::State_Bytes == decltype(state)::Num_Bytes);
		skein.hash_native( state.get(), buffer.get(), buffer_size );
        } /* os_reseed (u64_t) */

        template <size_t State_Bits>
        void
        Skein_PRNG<State_Bits>::get (void * const output_buffer,
                                     u64_t const  requested_bytes) {
		using std::memcpy;
		u64_t const buffer_size = requested_bytes + state.size();
		Sensitive_Dynamic_Buffer<u8_t> buffer{ buffer_size, is_lockable_( buffer_size ) };

		skein.hash( buffer.get(), state.get(), state.size(), buffer_size );
		memcpy( state.get(), buffer.get(), state.size() );
		memcpy( output_buffer, (buffer.get() + state.size()), requested_bytes );
        } /* get (u8_t*,u64_t) */

	template <size_t State_Bits>
	bool
	Skein_PRNG<State_Bits>::is_lockable_ (size_t const buf_size) {
#ifdef __SSC_MemoryLocking__
		return buf_size <= Max_Lockable_Bytes;
#else
		return false;
#endif
	}
}/* ! namespace ssc */
