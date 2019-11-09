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
#include <cstdio>
#include <ssc/general/symbols.hh>

#ifdef __UnixLike__
// For unix-like operating systems (that provide err.h), we can simply include err.h for error handling functions.
#	include <err.h>
#else
// For other operating systems, or unix-likes that do not provide err.h, we provide a replacement here.
// The replacement is in the global namespace, because for unix-like operating systems, the functions themselves are
// in the global namespace.
template <typename... Arg_Pack>
inline void
errx (int error_code, char const *format, Arg_Pack... args) {
	if constexpr(sizeof...(args) == 0) {
		std::fputs( format, stderr );
		std::exit( error_code );
	} else {
		std::fprintf( stderr, format, args... );
		std::exit( error_code );
	}
}/*errx(int,char const*,Arg_Pack...)*/
#endif/*#ifdef __UnixLike__*/

// This overload allows for not specifying an exit code when it is irrelevant.
template <typename... Arg_Pack>
inline void
errx (char const *format, Arg_Pack... args) {
	if constexpr(sizeof...(args) == 0)
		errx( static_cast<int>(EXIT_FAILURE), format );
	else
		errx( static_cast<int>(EXIT_FAILURE), format, args... );
}/*errx(char const*,Arg_Pack...)*/
