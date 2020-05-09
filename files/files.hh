/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

/* SSC General Headers */
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/general/integers.hh>
/* C Standard Headers */
#include <cstdlib>
#include <cstdio>
/* C++ Standard Headers */
#include <string>

#if    defined (__UnixLike__)
/* Unix-like Headers */
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <unistd.h>
#	include <fcntl.h>
#elif  defined (__Win64__)
/* Windows Headers */
#	include <windows.h>
#else
#	error 'Unsupported OS'
#endif

namespace ssc
{

#if    defined (__UnixLike__)
	using OS_File_t = int;
	_CTIME_CONST (OS_File_t) Null_OS_File = -1;
#elif  defined (__Win64__)
	using OS_File_t = HANDLE;
	_CTIME_CONST (OS_File_t) Null_OS_File = nullptr;
#else
#	error 'Unsupported OS'
#endif

	/* Prototype all the inline functions defined in this header.
	 */
	[[nodiscard]] inline size_t	get_file_size (OS_File_t const);
	[[nodiscard]] inline size_t	get_file_size (char const *);
	[[nodiscard]] inline size_t	get_file_size (std::FILE *);
	[[nodiscard]] inline bool	file_exists   (char const *);
	inline void	check_file_name_sanity (std::string const &, size_t const);

	inline void	enforce_file_existence (_RESTRICT (char const *),
			                        bool const,
						_RESTRICT (char const *) = nullptr);

	[[nodiscard]] inline OS_File_t open_existing_os_file  (char const *, bool const);
	[[nodiscard]] inline OS_File_t create_os_file         (char const *);
	inline void	 close_os_file		(OS_File_t const);
	inline void	 set_os_file_size	(OS_File_t const, size_t const);

	size_t get_file_size (OS_File_t const os_file)
	{
		using namespace std;
#if    defined (__UnixLike__)
		struct stat stat_struct;
		if( fstat( os_file, &stat_struct ) == -1 )
			errx( "Error: Unable to fstat file descriptor #%d\n", os_file );
		return static_cast<size_t>(stat_struct.st_size);
#elif  defined (__Win64__)
		LARGE_INTEGER lg_int;
		if( GetFileSizeEx( os_file, &lg_int ) == 0 )
			errx( "Error: GetFileSizeEx() failed\n" );
		return static_cast<size_t>(lg_int.QuadPart);
#else
#	error 'Unsupported OS'
#endif
	} /* ~ size_t get_file_size(OS_File_t const) */

	size_t get_file_size (char const *filename)
	{
		using namespace std;
#if    defined (__UnixLike__)
		struct stat s;
		if( stat( filename, &s) != 0 )
			errx( "Error: Failed to stat() info about %s\n", filename );
		return static_cast<size_t>(s.st_size);
#elif  defined (__Win64__)
		OS_File_t os_file = open_existing_os_file( filename, true );
		size_t const size = get_file_size( os_file );
		close_os_file( os_file );
		return size;
#else
		size_t num_bytes = 0;
		FILE * stream = fopen( filename, "rb" );
		if (stream == nullptr)
			errx( "Error: Failed to open file %s with fopen()\n", filename );
		while (fgetc( stream ) != EOF)
			++num_bytes;
		if (fclose( stream ) == -1)
			errx( "Error: Failed to close file %s with fclose()\n", filename );
		return num_bytes;
#endif
	} /* ~ size_t get_file_size(char const*) */

	size_t get_file_size (std::FILE *file)
	{
		using namespace std;

		size_t num_bytes = 0;
		fpos_t position;
		if (fgetpos( file, &position ) == -1)
			errx( "Error: Failed to get file position with fgetpos()\n" );
		while (fgetc( file ) != EOF)
			++num_bytes;
		if (fsetpos( file, &position ) == -1)
			errx( "Error: Failed to set file position to its original position with fsetpos()\n" );
		return num_bytes;
	} /* ~ size_t get_file_size(FILE*) */
	
	bool file_exists (char const *filename)
	{
		using namespace std;

		bool exists = false;
		FILE *test = fopen( filename, "rb" );
		if (test != nullptr) {
			fclose( test );
			exists = true;
		}
		return exists;
	} /* ~ bool file_exists(char const*) */

	void check_file_name_sanity (std::string const &str, size_t const min_size)
	{
		if (str.size() < min_size)
			errx( "Error: Filename %s must have at least %zu character(s)\n", str.c_str(), min_size );
	} /* ~ check_file_name_sanity(std::string const&,size_t const) */

	void enforce_file_existence (_RESTRICT (char const *) filename,
			             bool const force_to_exist,
				     _RESTRICT (char const *) opt_error_msg)
	{
		using namespace std;

		bool const exists = file_exists( filename );
		if (exists) {
			// The file does exist.
			if (!force_to_exist)
				errx( "Error: The file %s seems to already exist.\n", filename );
		} else {
			// The file does not exist.
			if (force_to_exist)
				errx( "Error: The file %s does not seem to exist.\n", filename );
		}
	} /* ~ void enforce_file_existence(char const*,bool const,char const*) */

	OS_File_t open_existing_os_file (char const *filename, bool const readonly)
	{
		using namespace std;
		enforce_file_existence( filename, true );
#if    defined (__UnixLike__)
		using Read_Write_t = decltype(O_RDWR);
		int file_d;
		Read_Write_t const read_write_rights = (readonly ? O_RDONLY : O_RDWR);
		if( (file_d = open( filename, read_write_rights, static_cast<mode_t>(0600) )) == -1 )
			errx( "Error: Unable to open existing file %s with open()\n", filename );
		return file_d;
#elif  defined (__Win64__)
		using Read_Write_t = decltype(GENERIC_READ);
		HANDLE file_h;
		Read_Write_t const read_write_rights = (readonly ? GENERIC_READ : (GENERIC_READ|GENERIC_WRITE));
		if( (file_h = CreateFileA( filename, read_write_rights, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr )) == INVALID_HANDLE_VALUE )
			errx( "Error: Unable to open existing file %s with CreateFileA()\n", filename );
		return file_h;
#else
#	error 'Unsupported OS'
#endif
	} /* ~ OS_File_t open_existing_os_file(char const*,bool const) */

	OS_File_t create_os_file (char const *filename)
	{
		using namespace std;
		enforce_file_existence( filename, false );
#if    defined (__UnixLike__)
		int file_d;
		if( (file_d = open( filename, (O_RDWR|O_TRUNC|O_CREAT), static_cast<mode_t>(0600) )) == -1 )
			errx( "Error: Unable to create new file %s with open()\n", filename );
		return file_d;
#elif  defined (__Win64__)
		HANDLE file_h;
		if( (file_h = CreateFileA( filename, (GENERIC_READ|GENERIC_WRITE), 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr )) == INVALID_HANDLE_VALUE )
			errx( "Error: Unable to create file %s with CreateFileA()\n", filename );
		return file_h;
#else
#	error 'Unsupported OS'
#endif
	} /* ~ OS_File_t create_os_file(char const*) */

	void close_os_file (OS_File_t const os_file)
	{
		using namespace std;
#if    defined (__UnixLike__)
		if( close( os_file ) == -1 )
			errx( "Error: Wasn't able to close file descriptor %d\n", os_file );
#elif  defined (__Win64__)
		if( CloseHandle( os_file ) == 0 )
			errx( "Error: Wasn't able to close file handle\n" );
#else
#	error 'Unsupported OS'
#endif
	} /* ~ void close_os_file(OS_File_t const) */

	void set_os_file_size (OS_File_t const os_file, size_t const new_size)
	{
		using namespace std;
#if    defined (__UnixLike__)
		if( ftruncate( os_file, new_size ) == -1 )
			errx( "Error: Failed to set size of file descriptor %d to %zu\n", os_file, new_size );
#elif  defined (__Win64__)
		LARGE_INTEGER lg_int;
		lg_int.QuadPart = static_cast<decltype(lg_int.QuadPart)>(new_size);
		if( SetFilePointerEx( os_file, lg_int, nullptr, FILE_BEGIN ) == 0 )
			errx( "Error: Failed to SetFilePointerEx()\n" );
		if( SetEndOfFile( os_file ) == 0 )
			errx( "Error: Failed to SetEndOfFile()\n" );
#else
#	error 'Unsupported OS'
#endif
	} /* ~ void set_os_file_size(OS_File_t const,size_t const) */

}/* ~ namespace ssc */
