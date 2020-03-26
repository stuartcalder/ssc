/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
#include <ssc/files/files.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/error_conditions.hh>

#if    defined (__UnixLike__)
#	include <sys/mman.h>
#elif  defined (__Win64__)
#	include <windows.h>
#	include <memoryapi.h>
#else
#	error 'Unsupported OS'
#endif

namespace ssc
{
	struct _PUBLIC OS_Map
	{
		u8_t	  *ptr;
		u64_t     size;
		OS_File_t os_file;
#ifdef __Win64__
		OS_File_t win64_filemapping;
#endif
	};/* ~ struct OS_Map */

	inline void map_file (OS_Map &os_map, bool const readonly)
	{
		using namespace std;
#if    defined (__UnixLike__)
		decltype(PROT_READ) const readwrite_flag = (readonly ? PROT_READ : (PROT_READ|PROT_WRITE));
		os_map.ptr = static_cast<u8_t *>(mmap( nullptr, os_map.size, readwrite_flag, MAP_SHARED, os_map.os_file, 0 ));
		if (os_map.ptr == MAP_FAILED)
			errx( "Error: Failed to mmap() the file descriptor %d\n", os_map.os_file );
#elif  defined (__Win64__)
		decltype(PAGE_READONLY) page_readwrite_flag;
		decltype(FILE_MAP_READ) map_readwrite_flag;
		if (readonly) {
			page_readwrite_flag = PAGE_READONLY;
			map_readwrite_flag = FILE_MAP_READ;
		} else {
			page_readwrite_flag = PAGE_READWRITE;
			map_readwrite_flag = (FILE_MAP_READ|FILE_MAP_WRITE);
		}

		DWORD high_bits = static_cast<DWORD>(os_map.size >> 32);
		DWORD low_bits  = static_cast<DWORD>(os_map.size);
		os_map.win64_filemapping = CreateFileMappingA( os_map.os_file, nullptr, page_readwrite_flag, high_bits, low_bits, nullptr );
		if (os_map.win64_filemapping == nullptr)
			errx( "Error: Failed during CreateFileMappingA()\n" );
		os_map.ptr = static_cast<u8_t *>(MapViewOfFile( os_map.win64_filemapping, map_readwrite_flag, 0, 0, os_map.size ));
		if (os_map.ptr == nullptr)
			errx( "Error: Failed during MapViewOfFile()\n" );
#else
#	error 'Unsupported OS'
#endif
	}/* ~ void map_file (OS_Map&,bool const) */

	inline void unmap_file (OS_Map const &os_map)
	{
		using namespace std;
#if    defined (__UnixLike__)
		if (munmap( os_map.ptr, os_map.size ) == -1)
			errx( "Error: Failed to munmap()\n" );
#elif  defined (__Win64__)
		if (UnmapViewOfFile( static_cast<LPCVOID>(os_map.ptr) ) == 0)
			errx( "Error: Failed to UnmapViewOfFile()\n" );
		close_os_file( os_map.win64_filemapping );
#else
#	error 'Unsupported OS'
#endif
	}/* ~ void unmap_file (OS_Map const &) */

	inline void sync_map (OS_Map const &os_map)
	{
#if    defined (__UnixLike__)
		if (msync( os_map.ptr, os_map.size, MS_SYNC ) == -1)
			errx( "Error: Failed to msync()\n" );
#elif  defined (__Win64__)
		if (FlushViewOfFile( static_cast<LPCVOID>(os_map.ptr), os_map.size ) == 0)
			errx( "Error: Failed to FlushViewOfFile()\n" );
#else
#	error 'Unsupported OS'
#endif
	}/* ~ void sync_map (OS_Map const &) */

}/* ~ namespace ssc */
