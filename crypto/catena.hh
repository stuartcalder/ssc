/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/

#pragma once

#include <cstdlib>
#include <cstring>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS template <int State_Bits>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif
#ifndef CLASS
#	define CLASS Catena<State_Bits>
#else
#	error 'CLASS Already Defined'
#endif

namespace ssc
{
	TEMPLATE_ARGS
	class Catena
	{
		public:
			static_assert (CHAR_BIT == 8);
			_CTIME_CONST(int) State_Bytes = State_Bits / CHAR_BIT;

			using Skein_t = Skein<State_Bits>;

			Catena() = delete; // Disallow construction without arguments.
			Catena(Skein_t *sk);
		private:
			Skein_t *skein;
			/* Private procedures */
			void hash_first_ (u8_t *output, u8_t const *alpha, u8_t const *beta);
	}; /* ~ class Catena */

	TEMPLATE_ARGS
	void CLASS::hash_first_ (u8_t *output, u8_t const *alpha, u8_t const *beta)
	{
		u8_t buffer [State_Bytes * 2];
		memcpy( buffer, alpha, State_Bytes );
		memcpy( (buffer + State_Bytes), beta, State_Bytes );
		skein->hash_native( buffer, buffer, sizeof(buffer) );
	} /* ~ hash_first_(u8_t*,u8_t*,u8_t*) */

}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
