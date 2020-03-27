/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */

#pragma once

#include <cstdlib>
#include <cstring>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS template <typename Hash_Func_t, \
	                               char const *Hash_Func_Name>//TODO
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif
#ifndef CLASS
#	define CLASS //TODO
#else
#	error 'CLASS Already Defined'
#endif

namespace ssc
{
	TEMPLATE_ARGS
	class Catena
	{
	public:
	/* CONSTRUCTORS */
		Catena (void) = delete;

	private:
	};
#if 0
	_CTIME_CONST(auto) Catena_ID_String = "Dragonfly-Skein512-Full";
	void _PUBLIC catena (u8_t       *output,   Skein_t * const skein,
		             u8_t       *password, int const       password_size,
		             u8_t const *salt,     int const       salt_size,
		             u8_t const *data,     int const       data_size,
		             u8_t const lambda,    u8_t const      min_garlic,
		             u8_t const garlic,    u8_t const      output_size,
		             u8_t const client,    u8_t const      tweak_id);
#endif
}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
