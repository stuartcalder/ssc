/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstdlib>
#include <cstdio>
#include <ssc/general/macros.hh>

#if    defined (SSC_OS_UNIXLIKE) && __has_include(<err.h>)
/* For unix-like operating systems that provide err.h, we can simply include err.h for error handling functions.
 */
#	include <err.h>
#else
/* For other operating systems, or unix-likes that do not provide err.h, we provide a replacement here.
 * The replacement is in the global namespace, because for unix-like operating systems, the functions themselves are
 * in the global namespace. 
 */
template <typename... Arg_Pack> inline void
errx (int error_code, char const *format, Arg_Pack... args)
{
	if constexpr (sizeof...(args) == 0) {
		std::fputs( format, stderr );
		std::exit( error_code );
	} else {
		std::fprintf( stderr, format, args... );
		std::exit( error_code );
	}
} // ~ void errx (int, char const*, Arg_Pack...)
#endif // ~ #if    defined (SSC_OS_UNIXLIKE) && __has_include(<err.h>)

/* This overload allows for not specifying an exit code when it is irrelevant.
 */
template <typename... Arg_Pack> inline void
errx (char const *format, Arg_Pack... args)
{
	if constexpr (sizeof...(args) == 0)
		errx( static_cast<int>(EXIT_FAILURE), format );
	else
		errx( static_cast<int>(EXIT_FAILURE), format, args... );
} // ~ void errx (char const*, Arg_Map...)

namespace ssc {
	struct
	Generic_Error
	{
		static constexpr auto &Alloc_Failure = "Error: Generic Allocation Failure!\n";
	}; // ~ struct Generic_Error
} // ~ namespace ssc
