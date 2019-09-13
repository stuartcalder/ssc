/*
Copyright 2019 Stuart Steven Calder

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <ssc/files/files.hh>
#include <ssc/general/integers.hh>

extern "C" {
#if defined(__OpenBSD__) || defined(__gnu_linux__)
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <unistd.h>
#	include <fcntl.h>
#elif defined(_WIN64)
#	include <windows.h>
#else
#	error "Only defined for Gnu/Linux and Win64"
#endif
}/* extern "C" */

namespace ssc {

	size_t
	get_file_size	(OS_File_t const os_file) {
		using namespace std;
#if defined(__OpenBSD__) || defined(__gnu_linux__)
		struct stat s;
		if (fstat( os_file, &s ) == -1) {
			fprintf( stderr, "Error: Unable to fstat file descriptor #%d\n", os_file );
			exit( EXIT_FAILURE );
		}
		return static_cast<size_t>(s.st_size);
#elif defined(_WIN64)
		LARGE_INTEGER large_int;
		if (GetFileSizeEx( os_file, &large_int ) == 0) {
			fputs( "Error: GetFileSizeEx() failed\n", stderr );
			exit( EXIT_FAILURE );
		}
		return static_cast<size_t>(large_int.QuadPart);
#else
#	error "OpenBSD, GNU/Linux, and Win64 supported platforms"
#endif
	}/* get_file_size */

	size_t
	get_file_size	(std::FILE * const file) {
		using namespace std;

		size_t num_bytes = 0;
		fpos_t position;
		if (fgetpos( file, &position ) == -1) {
			fprintf( stderr, "Failed to get file position\n" );
			exit( EXIT_FAILURE );
		}
		while (fgetc( file ) != EOF)
			++num_bytes;
		if (fsetpos( file, &position ) == -1) {
			fprintf( stderr, "Failed to set file position to its original position\n" );
			exit( EXIT_FAILURE );
		}
		return num_bytes;
	}

	size_t
	get_file_size	(char const * filename) {
	using namespace std;
#if defined(__OpenBSD__) || defined(__gnu_linux__)
		struct stat s;
		if (stat( filename, &s) != 0 ) {
			fprintf( stderr, "Failed to stat info about %s\n", filename );
			exit( EXIT_FAILURE );
		}
		return static_cast<size_t>(s.st_size);
#elif defined(_WIN64)
		OS_File_t file = open_existing_os_file( filename, true );
		size_t const size = get_file_size( file );
		close_os_file( file );
		return size;
#else // All other platforms
		size_t num_bytes = 0;
		FILE * stream = fopen( filename, "rb" );
		if (stream == nullptr) {
			fprintf( stderr, "Failed to open file %s\n", filename );
			exit( EXIT_FAILURE );
		}
		while (fgetc( stream ) != EOF)
			++num_bytes;
		if (fclose( stream ) == -1) {
			fprintf( stderr, "Failed to close file %s\n", filename );
			exit( EXIT_FAILURE );
		}
		return num_bytes;
#endif
	} /* ! get_file_size(const char * filename) */

	bool
	file_exists	(char const * filename) {
		using namespace std;

		bool exists = false;
		FILE * test = fopen( filename, "rb" );
		if (test != nullptr) {
			fclose( test );
			exists = true;
		}
		return exists;
	}

	void
	check_file_name_sanity	(std::string const & str,
				 size_t const        min_size) {
		if (str.size() < min_size) {
			std::fprintf( stderr, "Error: Filename %s must have at least %zu character(s)\n",
				      str.c_str(), min_size );
			std::exit( EXIT_FAILURE );
		}
	}

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

	OS_File_t
	open_existing_os_file	(char const * filename, bool const readonly) {
		using namespace std;
		enforce_file_existence( filename, true );
#if defined(__OpenBSD__) || defined(__gnu_linux__)
		int file_d;
		decltype(O_RDWR) read_write_rights;

		if (readonly)
			read_write_rights = O_RDONLY;
		else
			read_write_rights = O_RDWR;

		if ((file_d = open( filename, read_write_rights, static_cast<mode_t>(0600) )) == -1) {
			fputs( "Error: Unable to open file\n", stderr );
			exit( EXIT_FAILURE );
		}
		return file_d;
#elif defined(_WIN64)
		HANDLE file_h;
		decltype(GENERIC_READ) read_write_rights;

		if (readonly)
			read_write_rights = GENERIC_READ;
		else
			read_write_rights = (GENERIC_READ | GENERIC_WRITE);

		if ((file_h  = CreateFileA( filename, read_write_rights, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL )) == INVALID_HANDLE_VALUE) {
			fputs( "Error: Unable to open file\n", stderr );
			exit( EXIT_FAILURE );
		}
		return file_h;
#else
#	error "open_existing_os_file only defined for OpenBSD, GNU/Linux, & Win64"
#endif
	}/* ! open_existing_os_file */

	OS_File_t
	create_os_file	(char const * filename) {
		using namespace std;
		enforce_file_existence( filename, false );
#if defined(__OpenBSD__) || defined(__gnu_linux__)
		int file_d;
		if ((file_d = open( filename, (O_RDWR|O_TRUNC|O_CREAT), static_cast<mode_t>(0600) )) == -1) {
			fputs( "Error: Unable to create file\n", stderr );
			exit( EXIT_FAILURE );
		}
		return file_d;
#elif defined(_WIN64)
		HANDLE file_h;
		if ((file_h = CreateFileA( filename, (GENERIC_READ|GENERIC_WRITE), 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL )) == INVALID_HANDLE_VALUE) {
			fputs( "Error: Unable to create file\n", stderr );
			exit( EXIT_FAILURE );
		}
		return file_h;
#else
#	error "create_os_file defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! create_os_file */

	void
	close_os_file	(OS_File_t const os_file) {
		using namespace std;
#if defined(__OpenBSD__) || defined(__gnu_linux__)
		int ret_code = close( os_file );
		if (ret_code == -1) {
			fprintf( stderr, "Error: Wasn't able to close file descriptor %d\n", ret_code );
			exit( EXIT_FAILURE );
		}
#elif defined(_WIN64)
		if (CloseHandle( os_file ) == 0) {
			fputs( "Error: Was not able to close file\n", stderr );
			exit( EXIT_FAILURE );
		}
#else
#	error "Only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! close_os_file */

	void
	set_os_file_size	(OS_File_t const os_file, size_t const new_size) {
		using namespace std;
#if defined(__OpenBSD__) || defined(__gnu_linux__)
		if (ftruncate( os_file, new_size ) == -1) {
			fputs( "Error: Failed to set file size\n", stderr );
			exit( EXIT_FAILURE );
		}
#elif defined(_WIN64)
		LARGE_INTEGER large_int;
		large_int.QuadPart = static_cast<decltype(large_int.QuadPart)>(new_size);
		if (SetFilePointerEx( os_file, large_int, NULL, FILE_BEGIN ) == 0) {
			fputs( "Error: Failed to SetFilePointerEx()\n", stderr );
			exit( EXIT_FAILURE );
		}
		if (SetEndOfFile( os_file ) == 0) {
			fputs( "Error: Failed to SetEndOfFile()\n", stderr );
			exit( EXIT_FAILURE );
		}
#else
#	error "set_os_file_size only defined for OpenBSD, GNU/Linux, and Win64"
#endif
	}/* ! set_os_file_size */
}/* ! namespace ssc */
