/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <cstdio>

#include <ssc/crypto/operations.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/print.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/files/files.hh>
#include <ssc/files/os_map.hh>
#include <ssc/interface/terminal.hh>
#include <ssc/memory/os_memory_locking.hh>

#include "sspkdf.hh"
#include "cbc_v2.hh"

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error 'Already defined'
#endif

#if    defined (LOCK_MEMORY) || defined (UNLOCK_MEMORY)
#	error 'Already defined'
#endif

#ifdef __SSC_MemoryLocking__
#	define   LOCK_MEMORY(address,size)   lock_os_memory( address, size )
#	define UNLOCK_MEMORY(address,size) unlock_os_memory( address, size )
#else
#	define   LOCK_MEMORY(address,size)
#	define UNLOCK_MEMORY(address,size)
#endif

namespace ssc::crypto_impl::cbc_v2 {

	static u64_t
	calculate_encrypted_size	(u64_t const pre_encryption_size) {
		CTIME_CONST(int) File_Metadata_Size = CBC_V2_Header::Total_Size + MAC_Bytes;

		auto s = pre_encryption_size;
		if ( s < Block_Bytes )
			s = Block_Bytes;
		else
			s += (Block_Bytes - (s % Block_Bytes));
		return s + File_Metadata_Size;
	}

	void
	encrypt	(Input const & encr_input) {
		using namespace std;
		OS_Map input_map, output_map;

		// Open input file
		input_map.os_file = open_existing_os_file( encr_input.input_filename.c_str(), true );
		// Create output file
		output_map.os_file = create_os_file( encr_input.output_filename.c_str() );
		// Determine input file size
		input_map.size = get_file_size( input_map.os_file );
		// Calculate output file size
                output_map.size = calculate_encrypted_size( input_map.size );
		// Extend or shrink the output file to match calculated file size
		set_os_file_size( output_map.os_file, output_map.size );
		// Memory-Map the files
		map_file( input_map , true  );
		map_file( output_map, false );

		// We're going to need raw Threefish, Threefish in UBI mode for Skein, and Threefish in CBC mode for encryption.
		CTIME_CONST(int) CSPRNG_Buffer_Bytes = 128;
		CTIME_CONST(int) CSPRNG_CBC_Shared_Size = (CSPRNG_Buffer_Bytes > CBC_t::Buffer_Bytes ? CSPRNG_Buffer_Bytes : CBC_t::Buffer_Bytes);
		CTIME_CONST(int) Locked_Buffer_Size = []() -> int {
			int size = 0;
			size += (Password_Buffer_Bytes * 2); // Two password buffers
			size += Block_Bytes;		     // Derived key
			size += Threefish_t::Buffer_Bytes;   // Threefish data
			size +=       UBI_t::Buffer_Bytes;   // UBI data
			size += CSPRNG_CBC_Shared_Size;
			size += Supplement_Entropy_Buffer_Bytes;
			size += (size % sizeof(u64_t));
			return size;
		}();
		u8_t	locked_buffer [Locked_Buffer_Size];

		LOCK_MEMORY( locked_buffer, sizeof(locked_buffer) );

		CTIME_CONST(int) Password_Offset       = 0;
		CTIME_CONST(int) Password_Check_Offset = Password_Offset       + Password_Buffer_Bytes;
		CTIME_CONST(int) Derived_Key_Offset    = Password_Check_Offset + Password_Buffer_Bytes;
		CTIME_CONST(int) Threefish_Data_Offset = Derived_Key_Offset    + Block_Bytes;
		CTIME_CONST(int) UBI_Data_Offset       = Threefish_Data_Offset + Threefish_t::Buffer_Bytes;
		CTIME_CONST(int) CSPRNG_Data_Offset    = UBI_Data_Offset       + UBI_t::Buffer_Bytes;
		CTIME_CONST(int) Entropy_Data_Offset   = CSPRNG_Data_Offset + CSPRNG_CBC_Shared_Size;
		// After we use the CSPRNG, we can store the CBC data in the same memory region.
		CTIME_CONST(int) CBC_Data_Offset       = CSPRNG_Data_Offset;
		Threefish_t threefish{ reinterpret_cast<u64_t *>(locked_buffer + Threefish_Data_Offset) };
		UBI_t       ubi      { &threefish, (locked_buffer + UBI_Data_Offset) };
		Skein_t	    skein    { &ubi };
		CBC_V2_Header header;
		int	password_length;
		char	*password    = reinterpret_cast<char *>(locked_buffer + Password_Offset);
		{
			u8_t		*csprng_data = locked_buffer + CSPRNG_Data_Offset;
			CSPRNG_t	csprng   { &skein, csprng_data, CSPRNG_Buffer_Bytes };
			{
				static_assert (sizeof(char) == sizeof(u8_t));
				char	*password_check = reinterpret_cast<char *>(locked_buffer + Password_Check_Offset);

				password_length = obtain_password( password, password_check, Password_Prompt, Password_Reentry_Prompt, Password_Buffer_Bytes );
				zero_sensitive( password_check, Password_Buffer_Bytes );
			}
			if (encr_input.supplement_os_entropy) {
				u8_t	*entropy_data = locked_buffer + Entropy_Data_Offset;
				supplement_entropy( csprng, skein, entropy_data );
				zero_sensitive( entropy_data, Supplement_Entropy_Buffer_Bytes );
			}
			static_assert (sizeof(header.id) == sizeof(CBC_V2_ID));
			memcpy( header.id, CBC_V2_ID, sizeof(header.id) );
			header.total_size = static_cast<decltype(header.total_size)>(output_map.size);
			csprng.get( header.tweak      , sizeof(header.tweak)       );
			csprng.get( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
			csprng.get( header.cbc_iv     , sizeof(header.cbc_iv)      );
			zero_sensitive( csprng_data, CSPRNG_Buffer_Bytes );
		}
		header.num_iter   = encr_input.number_sspkdf_iterations;
		header.num_concat = encr_input.number_sspkdf_concatenations;
		// Copy header into the file, field at a time, advancing the pointer
		u8_t *out = output_map.ptr;
		{
			memcpy( out, header.id, sizeof(header.id) );
			out += sizeof(header.id);

			memcpy( out, &header.total_size, sizeof(header.total_size) );
			out += sizeof(header.total_size);

			memcpy( out, header.tweak, sizeof(header.tweak) );
			out += sizeof(header.tweak);

			memcpy( out, header.sspkdf_salt, sizeof(header.sspkdf_salt) );
			out += sizeof(header.sspkdf_salt);

			memcpy( out, header.cbc_iv, sizeof(header.cbc_iv) );
			out += sizeof(header.cbc_iv);

			memcpy( out, &header.num_iter, sizeof(header.num_iter) );
			out += sizeof(header.num_iter);

			memcpy( out, &header.num_concat, sizeof(header.num_concat) );
			out += sizeof(header.num_concat);
		}
		u8_t	*derived_key = locked_buffer + Derived_Key_Offset;
		sspkdf( derived_key, skein, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		zero_sensitive( password, Password_Buffer_Bytes );
		{
			u8_t	*cbc_data = locked_buffer + CBC_Data_Offset;
			threefish.rekey( derived_key, header.tweak );
			CBC_t	cbc{ &threefish, cbc_data };
			out += cbc.encrypt( out, input_map.ptr, input_map.size, header.cbc_iv );
			zero_sensitive( cbc_data, CBC_t::Buffer_Bytes );
		}
		{
			skein.message_auth_code( out, output_map.ptr, derived_key, output_map.size - MAC_Bytes, Block_Bytes, MAC_Bytes );
		}
		zero_sensitive( locked_buffer, sizeof(locked_buffer) );

		UNLOCK_MEMORY( locked_buffer, sizeof(locked_buffer) );

		// Synchronize everything written to the output file
		sync_map( output_map );
		// Unmap the input and output files
		unmap_file( input_map );
		unmap_file( output_map );
		// Close the input and output files
		close_os_file( input_map.os_file );
		close_os_file( output_map.os_file );
	}/* encrypt */
	void
	decrypt	(char const *__restrict input_filename,
		 char const *__restrict output_filename) {
		using namespace std;

		OS_Map input_map, output_map;

		// Create the input and output memory-maps.
		input_map.os_file  = open_existing_os_file( input_filename, true );
		output_map.os_file = create_os_file( output_filename );
		// Get the size of the input file.
		input_map.size = get_file_size( input_map.os_file );
		// For now, assume the size of the output file will be the same size as the input file.
		output_map.size = input_map.size;

		// Check to see if the input file is too small to have possibly been 3CRYPT_CBC_V2 encrypted.
		CTIME_CONST(decltype(input_map.size)) Minimum_Possible_File_Size = CBC_V2_Header::Total_Size + Block_Bytes + MAC_Bytes;

		if (input_map.size < Minimum_Possible_File_Size) {
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: Input file doesn't appear to be large enough to be a 3CRYPT_CBC_V2 encrypted file\n" );
		}
		// Set the output file to be `output_map.size` bytes.
		set_os_file_size( output_map.os_file, output_map.size );
		// Memory-map the input and output files.
		map_file( input_map , true  );
		map_file( output_map, false );
		// The `in` pointer is used for reading from the input files, and incremented as it's used to read.
		u8_t const *in = input_map.ptr;
		CBC_V2_Header header;
		// Copy all the fields of CBC_V2_Header from the memory-mapped input file into the header struct.
		{
			memcpy( header.id, in, sizeof(header.id) );
			in += sizeof(header.id);

			memcpy( &header.total_size, in, sizeof(header.total_size) );
			in += sizeof(header.total_size);

			memcpy( header.tweak, in, sizeof(header.tweak) );
			in += sizeof(header.tweak);

			memcpy( header.sspkdf_salt, in, sizeof(header.sspkdf_salt) );
			in += sizeof(header.sspkdf_salt);

			memcpy( header.cbc_iv, in, sizeof(header.cbc_iv) );
			in += sizeof(header.cbc_iv);

			memcpy( &header.num_iter, in, sizeof(header.num_iter) );
			in += sizeof(header.num_iter);

			memcpy( &header.num_concat, in, sizeof(header.num_concat) );
			in += sizeof(header.num_concat);
		}
		// Check for the magic "3CRYPT_CBC_V2" at the beginning of the file header.
		static_assert (sizeof(header.id) == sizeof(CBC_V2_ID));
		if (memcmp( header.id, CBC_V2_ID, sizeof(CBC_V2_ID) ) != 0) {
			unmap_file( input_map );
			unmap_file( output_map );
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: The input file doesn't appear to be a 3CRYPT_CBC_V2 encrypted file.\n" );
		}
		// Check that the input file is the same size as specified by the file header.
		if (header.total_size != static_cast<decltype(header.total_size)>(input_map.size)) {
			unmap_file( input_map );
			unmap_file( output_map );
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n", input_map.size, header.total_size );
		}
		CTIME_CONST(int) Locked_Buffer_Size = []() -> int {
			int size = 0;
			size += Password_Buffer_Bytes;
			size += Block_Bytes; // Derived key
			size += Threefish_t::Buffer_Bytes;
			size += UBI_t::Buffer_Bytes;
			size += CBC_t::Buffer_Bytes;
			size += (size % sizeof(u64_t));
			return size;
		}();

		CTIME_CONST(int) Password_Offset = 0;
		CTIME_CONST(int) Derived_Key_Offset = Password_Offset + Password_Buffer_Bytes;
		CTIME_CONST(int) Threefish_Offset   = Derived_Key_Offset + Block_Bytes;
		CTIME_CONST(int) UBI_Offset         = Threefish_Offset + Threefish_t::Buffer_Bytes;
		CTIME_CONST(int) CBC_Offset         = UBI_Offset;

		u8_t	locked_buffer [Locked_Buffer_Size];

		LOCK_MEMORY( locked_buffer, sizeof(locked_buffer) );

		static_assert	(sizeof(char) == sizeof(u8_t));
		int		password_length;
		char	* const password        = reinterpret_cast<char *>(locked_buffer + Password_Offset   );
		u8_t	* const derived_key     =                         (locked_buffer + Derived_Key_Offset);
		u64_t	* const threefish_data = reinterpret_cast<u64_t *>(locked_buffer + Threefish_Offset);
		u8_t	* const ubi_data        =                         (locked_buffer + UBI_Offset);
		u8_t	* const cbc_data        =                         (locked_buffer + CBC_Offset);

		Threefish_t threefish{ threefish_data };
		UBI_t	    ubi      { &threefish, ubi_data };
		Skein_t	    skein    { &ubi };
		password_length = obtain_password( password, Password_Prompt, Password_Buffer_Bytes );

		sspkdf( derived_key, skein, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		zero_sensitive( password, Password_Buffer_Bytes );
		{
			// Generate a MAC using the ciphertext and the derived key, and compare it to the MAC at the end of the input file.
			u8_t generated_mac [MAC_Bytes];
			{
				skein.message_auth_code( generated_mac,
							 input_map.ptr,
							 derived_key,
							 input_map.size - MAC_Bytes,
							 Block_Bytes,
							 sizeof(generated_mac) );
			}
			if (memcmp( generated_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes) != 0) {
				zero_sensitive( locked_buffer, sizeof(locked_buffer) );

				UNLOCK_MEMORY( locked_buffer, sizeof(locked_buffer) );

				unmap_file( input_map );
				unmap_file( output_map );
				close_os_file( input_map.os_file );
				close_os_file( output_map.os_file );
				remove( output_filename );
				errx( "Error: Authentication failed.\n"
				      "Possibilities: Wrong password, the file is corrupted, or it has been somehow tampered with.\n" );
			}
		}
		size_t plaintext_size;
		{
			threefish.rekey( derived_key, header.tweak );
			CBC_t cbc{ &threefish, cbc_data };
			CTIME_CONST(int) File_Metadata_Size = CBC_V2_Header::Total_Size + MAC_Bytes;
			plaintext_size = cbc.decrypt( output_map.ptr, in, input_map.size - File_Metadata_Size, header.cbc_iv );
		}
		zero_sensitive( locked_buffer, sizeof(locked_buffer) );

		UNLOCK_MEMORY( locked_buffer, sizeof(locked_buffer) );

		// Synchronize the output file.
		sync_map( output_map );
		// Unmap the memory-mapped input and output files.
		unmap_file( input_map );
		unmap_file( output_map );
		// Truncate the output file to the number of plaintext bytes.
		set_os_file_size( output_map.os_file, plaintext_size );
		// Close the input and output files.
		close_os_file( input_map.os_file );
		close_os_file( output_map.os_file );
	}/* decrypt */
	
	void
	dump_header	(char const *filename) {
		using std::memcpy, std::fprintf, std::fputs, std::putchar, std::exit;

		OS_Map os_map;
		os_map.os_file = open_existing_os_file( filename, true );
		os_map.size    = get_file_size( os_map.os_file );
		static constexpr auto const Minimum_Size = CBC_V2_Header::Total_Size + Block_Bytes + MAC_Bytes;
		if (os_map.size < Minimum_Size) {
			close_os_file( os_map.os_file );
			errx( "File `%s` looks too small to be CBC_V2 encrypted\n", filename );
		}
		map_file( os_map, true );

		CBC_V2_Header header;
		u8_t mac [MAC_Bytes];
		{
			u8_t const *p = os_map.ptr;

			memcpy( header.id, p, sizeof(header.id) );
			p += sizeof(header.id);

			memcpy( &header.total_size, p, sizeof(header.total_size) );
			p += sizeof(header.total_size);

			memcpy( header.tweak, p, sizeof(header.tweak) );
			p += sizeof(header.tweak);

			memcpy( header.sspkdf_salt, p, sizeof(header.sspkdf_salt) );
			p += sizeof(header.sspkdf_salt);

			memcpy( header.cbc_iv, p, sizeof(header.cbc_iv) );
			p += sizeof(header.cbc_iv);

			memcpy( &header.num_iter, p, sizeof(header.num_iter) );
			p += sizeof(header.num_iter);

			memcpy( &header.num_concat, p, sizeof(header.num_concat) );

			p = os_map.ptr + os_map.size - MAC_Bytes;
			memcpy( mac, p, sizeof(mac) );
		}
		unmap_file( os_map );
		close_os_file( os_map.os_file );

		fprintf( stdout,   "File Header ID             : %s\n", header.id );
		fprintf( stdout,   "File Size                  : %zu\n", header.total_size );
		fputs  (           "Threefish Tweak            : ", stdout );
		print_integral_buffer<u8_t>( header.tweak, sizeof(header.tweak) );
		fputs  (         "\nSSPKDF Salt                : ", stdout );
		print_integral_buffer<u8_t>( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
		fputs  (         "\nCBC Initialization Vector  : ", stdout );
		print_integral_buffer<u8_t>( header.cbc_iv, sizeof(header.cbc_iv) );
		fprintf( stdout, "\nNumber Iterations          : %u\n", header.num_iter );
		fprintf( stdout,   "Number Concatenations      : %u\n", header.num_concat );
		fputs(             "Message Authentication Code: ", stdout );
		print_integral_buffer<u8_t>( mac, sizeof(mac) );
		putchar( '\n' );
	}/* ! dump_header */
}/*namespace ssc::crypto_impl::cbc_v2*/
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
#undef CTIME_CONST
