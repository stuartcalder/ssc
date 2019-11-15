/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <ssc/files/files.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/error_conditions.hh>

#if    defined (__UnixLike__)
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <unistd.h>
#	include <fcntl.h>
#elif  defined (_WIN64)
#	ifndef WIN64_WINDOWS_H
#		include <windows.h>
#		define WIN64_WINDOWS_H
#	endif

#else
#	error "Only defined for OpenBSD, GNU/Linux, and Win64"
#endif

namespace ssc {

	size_t
	get_file_size	(OS_File_t const os_file) {
		using namespace std;
	/* On Unix-Like operating systems, directly use the fstat(2) call
	 * to get the size of a file, given a file descriptor (int).
	 */
#if    defined (__UnixLike__)
		struct stat s;
		if (fstat( os_file, &s ) == -1)
			errx( "Error: Unable to fstat file descriptor #%d\n", os_file );
		return static_cast<size_t>(s.st_size);
	/* On 64-bit MS Windows, given a HANDLE input,
	 * create a LARGE_INTEGER, and use GetFileSizeEx() to store the
	 * size of the file defined by the input HANDLE.
	 * Cast the size to size_t, and return it.
	 */
#elif  defined (_WIN64)
		LARGE_INTEGER large_int;
		if (GetFileSizeEx( os_file, &large_int ) == 0)
			errx( "Error: GetFileSizeEx() failed\n" );
		return static_cast<size_t>(large_int.QuadPart);
#else
#	error "OpenBSD, GNU/Linux, and Win64 are the only supported supported platforms."
#endif
	}/* get_file_size */

	size_t
	get_file_size	(std::FILE * const file) {
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
	}

	size_t
	get_file_size	(char const * filename) {
	using namespace std;
	/* On Unix-Like operating systems, directly use the stat(2) call with
	 * the `struct stat` datastructure to get the size of a file defined by
	 * a C-string.
	 */
#if    defined (__UnixLike__)
		struct stat s;
		if (stat( filename, &s) != 0 )
			errx( "Error: Failed to stat() info about %s\n", filename );
		return static_cast<size_t>(s.st_size);
		
	/* On 64-bit MS Windows, use our already existing open_existing_os_file(), get_file_size(), and close_os_file()
	 * functions to get the size of a file in bytes, given an input C-string.
	 */
#elif  defined (_WIN64)
		OS_File_t file = open_existing_os_file( filename, true );
		size_t const size = get_file_size( file );
		close_os_file( file );
		return size;
	/* All other platforms. */
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
	} /* ! get_file_size(const char * filename) */

	/* Use the standard C-library stdio.h functions to open
	 * a FILE. If we successfully open the file, assume that file to exist.
	 * If we do not successfully open it, assume that file does not exist.
	 */
	bool
	file_exists	(char const * filename) {
		using namespace std;

		bool exists = false;
		FILE *test = fopen( filename, "rb" );
		if (test != nullptr) {
			fclose( test );
			exists = true;
		}
		return exists;
	}

	/* Ensure that the std::string parameter is within a certain minimum size.
	 * If it isn't, error out.
	 */
	void
	check_file_name_sanity	(std::string const & str,
				 size_t const        min_size) {
		if (str.size() < min_size)
			errx( "Error: Filename `%s` must have at least %zu character(s)\n", str.c_str(), min_size );
	}

	/* Check whether a given file exists for an input C-string filename.
	 * Then, if we the force the file to exist and it doesn't exist, error out.
	 * If we force the file to NOT exist and it DOES exist, error out.
	 */
	void
	enforce_file_existence	(char const * const __restrict filename,
				 bool const                    force_to_exist,
				 char const * const __restrict opt_error_msg) {
		bool const exists = file_exists( filename );
		if (exists) {
			if (force_to_exist)
				return;
			else { // Error: File exists when it shouldn't
				if (opt_error_msg == nullptr)
					std::fprintf( stderr, "Error: The file '%s' seems to already exist.\n", filename );
				else
					std::fputs( opt_error_msg, stderr );
			}
		} else { // doesn't exist
			if (force_to_exist) { // Error: File doesn't exist when it should
				if (opt_error_msg == nullptr)
					std::fprintf( stderr, "Error: The file '%s' doesn't seem to exist.\n", filename );
				else
					std::fputs( opt_error_msg, stderr );
			}
			else
				return;
		}
		std::exit( EXIT_FAILURE );
	}/* ! enforce_file_existence */

	/* Open a file with Operating-System defined file handlers, given
	 * an input C-string and a true boolean for readonly, a false
	 * boolean for read/write.
	 */
	OS_File_t
	open_existing_os_file	(char const * filename, bool const readonly) {
		using namespace std;
		enforce_file_existence( filename, true );
	/* On Unix-Like operating systems, we return an int representing an OS file-descriptor.
	 */
#if    defined (__UnixLike__)
		int file_d;
		decltype(O_RDWR) read_write_rights;

		if (readonly)
			read_write_rights = O_RDONLY;
		else
			read_write_rights = O_RDWR;

		if ((file_d = open( filename, read_write_rights, static_cast<mode_t>(0600) )) == -1)
			errx( "Error: Unable to open existing file `%s` with open()\n", filename );
		return file_d;
	/* On Win64, we return a HANDLE representing an OS file-handle.
	 */
#elif  defined (_WIN64)
		HANDLE file_h;
		decltype(GENERIC_READ) read_write_rights;

		if (readonly)
			read_write_rights = GENERIC_READ;
		else
			read_write_rights = (GENERIC_READ | GENERIC_WRITE);

		if ((file_h  = CreateFileA( filename, read_write_rights, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr )) == INVALID_HANDLE_VALUE)
			errx( "Error: Unable to open existing file `%s` with CreateFileA()\n", filename );
		return file_h;
#else
#	error "open_existing_os_file only defined for OpenBSD, GNU/Linux, & Win64"
#endif
	}/* ! open_existing_os_file */

	OS_File_t
	create_os_file	(char const * filename) {
		using namespace std;
		enforce_file_existence( filename, false );
#if    defined (__UnixLike__)
		int file_d;
		if ((file_d = open( filename, (O_RDWR|O_TRUNC|O_CREAT), static_cast<mode_t>(0600) )) == -1)
			errx( "Error: Unable to create new file `%s` with open()\n", filename );
		return file_d;
#elif  defined (_WIN64)
		HANDLE file_h;
		if ((file_h = CreateFileA( filename, (GENERIC_READ|GENERIC_WRITE), 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr )) == INVALID_HANDLE_VALUE)
			errx( "Error: Unable to create file `%s` with CreateFileA()\n", filename );
		return file_h;
#else
#	error "create_os_file defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! create_os_file */

	void
	close_os_file	(OS_File_t const os_file) {
		using namespace std;
#if    defined (__UnixLike__)
		if (close( os_file ) == -1)
			errx( "Error: Wasn't able to close file descriptor %d\n", os_file );
#elif  defined (_WIN64)
		if (CloseHandle( os_file ) == 0)
			errx( "Error: Wasn't able to close file handle\n" );
#else
#	error "Only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! close_os_file */

	void
	set_os_file_size	(OS_File_t const os_file, size_t const new_size) {
		using namespace std;
#if    defined (__UnixLike__)
		if (ftruncate( os_file, new_size ) == -1)
			errx( "Error: Failed to set size of file descriptor `%d` to `%zu`\n", os_file, new_size );
#elif  defined (_WIN64)
		LARGE_INTEGER large_int;
		large_int.QuadPart = static_cast<decltype(large_int.QuadPart)>(new_size);
		if (SetFilePointerEx( os_file, large_int, nullptr, FILE_BEGIN ) == 0)
			errx( "Error: Failed to SetFilePointerEx()\n" );
		if (SetEndOfFile( os_file ) == 0)
			errx( "Error: Failed to SetEndOfFile()\n" );
#else
#	error "set_os_file_size only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! set_os_file_size */
}/* ! namespace ssc */
