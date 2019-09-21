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
#include <string>
#include <ssc/general/symbols.hh>

#ifdef _WIN64
extern "C" {
#   include <windows.h>
}
#endif

namespace ssc {

#if defined(__OpenBSD__) || defined(__gnu_linux__)
	using OS_File_t = int;
#elif defined(_WIN64)
	using OS_File_t = HANDLE;
#else
#   error "Unsupported platform"
#endif

	size_t DLL_PUBLIC
	get_file_size	(OS_File_t const);

	size_t DLL_PUBLIC
	get_file_size   (char const * filename);

	size_t DLL_PUBLIC
	get_file_size   (std::FILE const * const file);
	
	bool DLL_PUBLIC
	file_exists     (char const * filename);

	void DLL_PUBLIC
	check_file_name_sanity (std::string const & str, size_t const   min_size);

	void DLL_PUBLIC
	enforce_file_existence	(char const * const __restrict filename,
				 bool const                    force_to_exist,
				 char const * const __restrict opt_error_msg = nullptr);

	OS_File_t DLL_PUBLIC
	open_existing_os_file	(char const * filename, bool const readonly);

	OS_File_t DLL_PUBLIC
	create_os_file	(char const * filename);

	void DLL_PUBLIC
	close_os_file    (OS_File_t const os_file); 

	void DLL_PUBLIC
	set_os_file_size (OS_File_t const os_file, size_t const new_size);
}/* ! namespace ssc */
