/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
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
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>

#ifdef TEMPLATE_PARAMETERS
#	error 'TEMPLATE_PARAMETERS Already Defined'
#else
#	define TEMPLATE_PARAMETERS template <int State_Bits,int Max>
#endif

#ifdef CLASS
#	error 'CLASS Already Defined'
#else
#	define CLASS Skein_CSPRNG<State_Bits,Max>
#endif

namespace ssc {
	static_assert (CHAR_BIT == 8);
        template <int State_Bits, int Max = (State_Bits / CHAR_BIT)>
        class Skein_CSPRNG {
        public:
		static_assert (State_Bits == 256 || State_Bits == 512 || State_Bits == 1024);
		using Skein_t = Skein<State_Bits>;
		_CTIME_CONST(int) Max_Bytes_Per_Call = Max;
		_CTIME_CONST(int) State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST(int) Buffer_Bytes = (State_Bytes * 2) + Max_Bytes_Per_Call;
		static_assert (Buffer_Bytes >= (State_Bytes * 3));

		Skein_CSPRNG () = delete;
		Skein_CSPRNG (Skein_t *sk, u8_t *buf)
			: skein{ sk }, state{ buf }
		{
			obtain_os_entropy( state, State_Bytes );
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


	TEMPLATE_PARAMETERS
	void CLASS::reseed (void const * const seed)
	{
		using std::memcpy;

		u8_t	*state_copy = state      + State_Bytes;
		u8_t	*seed_copy  = state_copy + State_Bytes;

		memcpy( state_copy, state, State_Bytes );
		memcpy( seed_copy , seed , State_Bytes );
		
		static_assert (Skein_t::State_Bytes == State_Bytes);
		skein->hash_native( state, state_copy, (State_Bytes * 2) );
        } /* reseed (u8_t *,u64_t) */

	TEMPLATE_PARAMETERS
        void CLASS::os_reseed (void)
	{
		using std::memcpy;

		u8_t	*state_copy = state      + State_Bytes;
		u8_t	*seed       = state_copy + State_Bytes;

		memcpy( state_copy, state, State_Bytes );
		obtain_os_entropy( seed, State_Bytes );
		static_assert (Skein_t::State_Bytes == State_Bytes);
		skein->hash_native( state, state_copy, (State_Bytes * 2) );
        } /* os_reseed (u64_t) */

	TEMPLATE_PARAMETERS
        void CLASS::get (void * const output_buffer, u64_t const requested_bytes)
	{
#ifndef __SSC_DISABLE_RUNTIME_CHECKS
		if (requested_bytes > Max_Bytes_Per_Call)
			errx( "Error: Skein_CSPRNG Max_Bytes_Per_Call is %d; %d bytes were requested.\n", Max_Bytes_Per_Call, requested_bytes );
#endif /* __SSC_DISABLE_RUNTIME_CHECKS */
		using std::memcpy;
		
		u8_t	*scratch_buffer = state + State_Bytes;

		skein->hash( scratch_buffer, state, State_Bytes, (requested_bytes + State_Bytes) );
		memcpy( state        , scratch_buffer                , State_Bytes     );
		memcpy( output_buffer, (scratch_buffer + State_Bytes), requested_bytes );
        } /* get (u8_t *,u64_t) */
}/* ! namespace ssc */
#undef CLASS
#undef TEMPLATE_PARAMETERS
