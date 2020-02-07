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

namespace ssc {
        template <int State_Bits>
        class Skein_CSPRNG {
        public:
		static_assert	 (CHAR_BIT == 8);
		static_assert	 (State_Bits == 256 || State_Bits == 512 || State_Bits == 1024);
		using Skein_t =  Skein<State_Bits>;
		_CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST(int)	Minimum_Buffer_Size = State_Bytes * 2;
		_CTIME_CONST(int)	Buffer_Bytes = State_Bytes * 3;

		Skein_CSPRNG (Skein_t *sk, u8_t *buf)
			: skein{ sk }, state{ buf }
		{
		}
		
                /* void reseed(seed,seed_bytes)
                 *      Copies in ${seed_bytes} bytes into the state, and
                 *      hashes them. */
		void
		reseed (void const * const seed);

                /* void os_reseed(seed_bytes)
                 *      Reseeds the state using ${seed_bytes} bytes of entropy
                 *      received from the operating system. */
		void
		os_reseed (void);

                /* void get(output_buffer,requested_bytes)
                 *      Writes ${requested_bytes} pseudorandom bytes into the ${output_buffer}. */
                void
                get (void * const output_buffer,
                     u64_t const  requested_bytes);
        private:
		Skein_t *skein;
		/* Layout
		 * (State_Bytes) (State_Bytes * 2)
		 * [State      ],[Scratch Buffer ]
		 */
		u8_t	*state;

        }; /* ! class Skein_CSPRNG */


        template <int State_Bits>
        void
	Skein_CSPRNG<State_Bits>::reseed (void const * const seed) {
		using std::memcpy;

		u8_t	*state_copy = state      + State_Bytes;
		u8_t	*seed_copy  = state_copy + State_Bytes;

		memcpy( state_copy, state, State_Bytes );
		memcpy( seed_copy , seed , State_Bytes );
		
		static_assert	(Skein_t::State_Bytes == State_Bytes);
		skein->hash_native( state, state_copy, (State_Bytes * 2) );
        } /* reseed (u8_t *,u64_t) */

        template <int State_Bits>
        void
        Skein_CSPRNG<State_Bits>::os_reseed (void) {
		using std::memcpy;

		u8_t	*state_copy = state      + State_Bytes;
		u8_t	*seed       = state_copy + State_Bytes;

		memcpy( state_copy, state, State_Bytes );
		obtain_os_entropy( seed, State_Bytes );
		static_assert (Skein_t::State_Bytes == State_Bytes);
		skein->hash_native( state, state_copy, (State_Bytes * 2) );
        } /* os_reseed (u64_t) */

        template <int State_Bits>
        void
        Skein_CSPRNG<State_Bits>::get (void * const output_buffer, u64_t const requested_bytes) {
		using std::memcpy;
		
		u8_t	*scratch_buffer = state + State_Bytes;

		skein->hash( scratch_buffer, state, State_Bytes, (requested_bytes + State_Bytes) );
		memcpy( state        , scratch_buffer                , State_Bytes     );
		memcpy( output_buffer, (scratch_buffer + State_Bytes), requested_bytes );
        } /* get (u8_t *,u64_t) */
}/* ! namespace ssc */
