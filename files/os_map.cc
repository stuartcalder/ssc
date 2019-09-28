/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/files/os_map.hh>

extern "C" {
#if defined(__Unix_Like__)
#	include <sys/mman.h>
#elif defined(_WIN64)
#	ifndef WIN64_WINDOWS_H
#		include <windows.h>
#		define WIN64_WINDOWS_H
#	endif

#	ifndef WIN64_MEMORYAPI_H
#		include <memoryapi.h>
#		define WIN64_MEMORYAPI_H
#	endif

#else
#	error "Only defined for OpenBSD, GNU/Linux, and Win64"
#endif
}/* extern "C" */

namespace ssc {
	void
	map_file	(OS_Map & os_map, bool const readonly) {
#if defined(__Unix_Like__)
		decltype(PROT_READ) const readwrite_flag = (readonly ? PROT_READ : (PROT_READ | PROT_WRITE));
		os_map.ptr = static_cast<u8_t *>(mmap( nullptr, os_map.size, readwrite_flag, MAP_SHARED, os_map.os_file, 0 ));
		if ( os_map.ptr == MAP_FAILED ) {
			fputs( "Error: Failed to open map\n", stderr );
			exit( EXIT_FAILURE );
		}
#elif defined(_WIN64)
		decltype(PAGE_READONLY) page_readwrite_flag;
		decltype(FILE_MAP_READ) map_readwrite_flag;
		if (readonly) {
			page_readwrite_flag = PAGE_READONLY;
			map_readwrite_flag = FILE_MAP_READ;
		} else {
			page_readwrite_flag = PAGE_READWRITE;
			map_readwrite_flag = (FILE_MAP_READ | FILE_MAP_WRITE);
		}

		DWORD high_bits = static_cast<DWORD>(os_map.size >> 32);
		DWORD low_bits  = static_cast<DWORD>(os_map.size);
		os_map.win64_filemapping = CreateFileMappingA( os_map.os_file, NULL, page_readwrite_flag, high_bits, low_bits, NULL );

		if (os_map.win64_filemapping == NULL) {
			fputs( "Error: Failed during CreateFileMappingA()\n", stderr );
			exit( EXIT_FAILURE );
		}
		os_map.ptr = static_cast<u8_t *>(MapViewOfFile( os_map.win64_filemapping, map_readwrite_flag, 0, 0, os_map.size ));
		if (os_map.ptr == NULL) {
			fputs( "Error: Failed to MapViewOfFile()\n", stderr );
			exit( EXIT_FAILURE );
		}
#else
#	error "map_file only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! map_file */


	void
	unmap_file	(OS_Map const & os_map) {
		using namespace std;
#if defined(__Unix_Like__)
		if (munmap( os_map.ptr, os_map.size ) == -1) {
			fputs( "Error: Failed to unmap file\n", stderr );
			exit( EXIT_FAILURE );
		}
#elif defined(_WIN64)
		if (UnmapViewOfFile( static_cast<LPCVOID>(os_map.ptr) ) == 0) {
			fputs( "Error: Failed to unmap file\n", stderr );
			exit( EXIT_FAILURE );
		}
		close_os_file( os_map.win64_filemapping );
#else
#	error "unmap_file only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! unmap_file */

	void
	sync_map	(OS_Map const & os_map) {
		using namespace std;
#if defined(__Unix_Like__)
		if (msync( os_map.ptr, os_map.size, MS_SYNC ) == -1) {
			fputs( "Error: Failed to sync mmap()\n", stderr );
			exit( EXIT_FAILURE );
		}
#elif defined(_WIN64)
		if (FlushViewOfFile( static_cast<LPCVOID>(os_map.ptr), os_map.size ) == 0) {
			fputs( "Error: Failed to FlushViewOfFile()\n", stderr );
			exit( EXIT_FAILURE );
		}
#else
#	error "sync_map only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! sync_map */


}/* ! namespace ssc */
