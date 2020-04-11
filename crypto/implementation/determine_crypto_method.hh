/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/files/os_map.hh>

#if    (!defined (__SSC_CBC_V2__) && !defined (__SSC_CTR_V1__))
#	error 'Crypto implementations must be #included before this file.'
#endif

namespace ssc::crypto_impl
{

	// Enums
	enum class Crypto_Method_E {
		None,
#ifdef __SSC_CBC_V2__
		CBC_V2,
#endif
#ifdef __SSC_CTR_V1__
		CTR_V1,
#endif
		Terminating_Enum
	};/*enum class Crypto_Method_E*/
	static_assert (Crypto_Method_E::Terminating_Enum > 1);
	_CTIME_CONST (int) Number_Crypto_Methods = Crypto_Method_E::Terminating_Enum - 1;

	// Compile-Time constants
	_CTIME_CONST (int) Biggest_ID_String_Size = []() {
		int s = 0;
#ifdef __SSC_CBC_V2__
		if (sizeof(cbc_v2::CBC_V2_ID) > s)
			s = sizeof(cbc_v2::CBC_V2_ID);
#endif
#ifdef __SSC_CTR_V1__
		if (sizeof(ctr_v1::CTR_V1_ID) > s)
			s = sizeof(ctr_v1::CTR_V1_ID);
#endif
		return s;
	}();
	_CTIME_CONST (int) Smallest_ID_String_Size = []() {
		int s = Biggest_ID_String_Size;
#ifdef __SSC_CBC_V2__
		if (sizeof(cbc_v2::CBC_V2_ID) < s)
			s = sizeof(cbc_v2::CBC_V2_ID);
#endif
#ifdef __SSC_CTR_V1__
		if (sizeof(ctr_v1::CTR_V1_ID) < s)
			s = sizeof(ctr_v1::CTR_V1_ID);
#endif
		return s;
	}();

	inline Crypto_Method_E determine_crypto_method (OS_Map &os_map)
	{
		if( os_map.size < Smallest_ID_String_Size ) {
			return Crypto_Method_E::None;
		}
#ifdef __SSC_CBC_V2__
		{
			using namespace cbc_v2;
			static_assert (sizeof(CBC_V2_ID) >= Smallest_ID_String_Size);
			static_assert (sizeof(CBC_V2_ID) <= Biggest_ID_String_Size);
			if( memcmp( os_map.ptr, CBC_V2_ID, sizeof(CBC_V2_ID) ) == 0 ) {
				return Crypto_Method_E::CBC_V2;
			}

		}
#endif
#ifdef __SSC_CTR_V1__
		{
			using namespace ctr_v1;
			static_assert (sizeof(CTR_V1_ID) >= Smallest_ID_String_Size);
			static_assert (sizeof(CTR_V1_ID) <= Biggest_ID_String_Size);
			if( memcmp( os_map.ptr, CTR_V1_ID, sizeof(CTR_V1_ID) ) == 0 ) {
				return Crypto_Method_E::CTR_V1;
			}
		}
#endif
			return Crypto_Method_E::None;
	}

#if 0
	// Functions
	inline Crypto_Method_E determine_crypto_method (char const *filename)
	{
		Crypto_Method_E method = Crypto_Method_E::None;
		// Memory map the file.
		OS_Map os_map;
		os_map.os_file = open_existing_os_file( filename, true );
		os_map.size = get_file_size( os_map.os_file );
		// Check the size of file...
		if (os_map.size < Smallest_ID_String_Size()) {
			close_os_file( os_map.os_file );
			return method;
		}
		map_file( os_map, true );
		// Check if the file is encrypted by a known method...
#ifdef __SSC_CBC_V2__
		{
			using namespace cbc_v2;
			_CTIME_CONST(size_t) Smallest_ID = Smallest_ID_String_Size();
			_CTIME_CONST(size_t) Biggest_ID = Biggest_ID_String_Size();
			static_assert (sizeof(CBC_V2_ID) >= Smallest_ID);
			static_assert (sizeof(CBC_V2_ID) <= Biggest_ID);
			if (memcmp( os_map.ptr, CBC_V2_ID, sizeof(CBC_V2_ID) ) == 0) {
				method = Crypto_Method_E::CBC_V2;
				goto End_Methods_L;
			}

		}
#endif
#ifdef __SSC_CTR_V1__
		{
			using namespace ctr_v1;
			_CTIME_CONST(size_t) Smallest_ID = Smallest_ID_String_Size();
			_CTIME_CONST(size_t) Biggest_ID = Biggest_ID_String_Size();
			static_assert (sizeof(CTR_V1_ID) >= Smallest_ID);
			static_assert (sizeof(CTR_V1_ID) <= Biggest_ID);
			if (memcmp( os_map.ptr, CTR_V1_ID, sizeof(CTR_V1_ID) ) == 0) {
				method = Crypto_Method_E::CTR_V1;
				goto End_Methods_L;
			}
		}
#endif
End_Methods_L:
		// Cleanup.
		unmap_file( os_map );
		close_os_file( os_map.os_file );
		return method;
	}/* ~ Crypto_Method_e determine_crypto_method(char const*) */
#endif
}/* ~ namespace ssc::crypto_impl */
