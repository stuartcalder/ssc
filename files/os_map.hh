/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

/* SSC General Headers */
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/general/integers.hh>
/* SSC File I/O Headers */
#include <ssc/files/files.hh>

#if    defined (__UnixLike__)
/* Unix-like Headers */
#	include <sys/mman.h>
#elif  defined (__Win64__)
/* Windows Headers */
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
		using Map_Read_Write_t = decltype(PROT_READ);
		Map_Read_Write_t const readwrite_flag = (readonly ? PROT_READ : (PROT_READ|PROT_WRITE));
		os_map.ptr = static_cast<u8_t *>(mmap( nullptr, os_map.size, readwrite_flag, MAP_SHARED, os_map.os_file, 0 ));
		if (os_map.ptr == MAP_FAILED)
			errx( "Error: Failed to mmap() the file descriptor %d\n", os_map.os_file );
#elif  defined (__Win64__)
		using Page_Read_Write_t = decltype(PAGE_READONLY);
		using Map_Read_Write_t  = decltype(FILE_MAP_READ);
		Page_Read_Write_t page_readwrite_flag;
		Map_Read_Write_t  map_readwrite_flag;
		if (readonly) {
			page_readwrite_flag = PAGE_READONLY;
			map_readwrite_flag = FILE_MAP_READ;
		} else {
			page_readwrite_flag = PAGE_READWRITE;
			map_readwrite_flag = (FILE_MAP_READ|FILE_MAP_WRITE);
		}

		static_assert (sizeof(os_map.size) == 8);
		static_assert (sizeof(DWORD) == 4);
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

	inline void nullify_map (OS_Map &os_map)
	{
		os_map.ptr = nullptr;
		os_map.size = 0;
		os_map.os_file = Null_OS_File;
#ifdef __Win64__
		os_map.win64_filemapping = Null_OS_File;
#endif
	}

}/* ~ namespace ssc */
