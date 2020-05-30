/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/files/os_map.hh>

#if    (!defined (SSC_FEATURE_DRAGONFLY_V1) && !defined (SSC_FEATURE_CBC_V2))
#	error 'Crypto implementations must be #included before this file.'
#endif

namespace ssc::crypto_impl
{

	// Enums
	enum class Crypto_Method_E{
		None,
#ifdef SSC_FEATURE_DRAGONFLY_V1
		Dragonfly_V1,
#endif
#ifdef SSC_FEATURE_CBC_V2
		CBC_V2,
#endif
		Terminating_Enum
	};/*enum class Crypto_Method_E*/
	static_assert (static_cast<int>(Crypto_Method_E::Terminating_Enum) > 1);
	static constexpr int Number_Crypto_Methods = static_cast<int>(Crypto_Method_E::Terminating_Enum) - 1;

	// Compile-Time constants
	static constexpr int Biggest_ID_String_Size = []() {
		int s = 0;
#ifdef SSC_FEATURE_DRAGONFLY_V1
		if (sizeof(dragonfly_v1::Dragonfly_V1_ID) > s)
			s = sizeof(dragonfly_v1::Dragonfly_V1_ID);
#endif
#ifdef SSC_FEATURE_CBC_V2
		if (sizeof(cbc_v2::CBC_V2_ID) > s)
			s = sizeof(cbc_v2::CBC_V2_ID);
#endif
		return s;
	}();
	static constexpr int Smallest_ID_String_Size = []() {
		int s = Biggest_ID_String_Size;
#ifdef SSC_FEATURE_DRAGONFLY_V1
		if (sizeof(dragonfly_v1::Dragonfly_V1_ID) < s)
			s = sizeof(dragonfly_v1::Dragonfly_V1_ID);
#endif
#ifdef SSC_FEATURE_CBC_V2
		if (sizeof(cbc_v2::CBC_V2_ID) < s)
			s = sizeof(cbc_v2::CBC_V2_ID);
#endif
		return s;
	}();

	inline Crypto_Method_E
	determine_crypto_method (OS_Map &os_map)
	{
		if( os_map.size < Smallest_ID_String_Size ) {
			return Crypto_Method_E::None;
		}
#ifdef SSC_FEATURE_DRAGONFLY_V1
		{
			using namespace dragonfly_v1;
			static_assert (sizeof(Dragonfly_V1_ID) >= Smallest_ID_String_Size);
			static_assert (sizeof(Dragonfly_V1_ID) <= Biggest_ID_String_Size);
			if( memcmp( os_map.ptr, Dragonfly_V1_ID, sizeof(Dragonfly_V1_ID) ) == 0 ) {
				return Crypto_Method_E::Dragonfly_V1;
			}
		}
#endif
#ifdef SSC_FEATURE_CBC_V2
		{
			using namespace cbc_v2;
			static_assert (sizeof(CBC_V2_ID) >= Smallest_ID_String_Size);
			static_assert (sizeof(CBC_V2_ID) <= Biggest_ID_String_Size);
			if( memcmp( os_map.ptr, CBC_V2_ID, sizeof(CBC_V2_ID) ) == 0 ) {
				return Crypto_Method_E::CBC_V2;
			}

		}
#endif
		return Crypto_Method_E::None;
	}

}/* ~ namespace ssc::crypto_impl */
