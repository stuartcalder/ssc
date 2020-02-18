/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef __SSC_ENABLE_EXPERIMENTAL
#	error 'This is experimental.'
#endif

#include <cstdio>

#include "ctr_v1.hh"
#include "sspkdf.hh"

#include <ssc/general/macros.hh>
#include <ssc/general/print.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/files/files.hh>
#include <ssc/files/os_map.hh>
#include <ssc/interface/terminal.hh>
#include <ssc/memory/os_memory_locking.hh>

#if    defined (LOCK_MEMORY) || defined (UNLOCK_MEMORY)
#	error 'LOCK_MEMORY or UNLOCK_MEMORY Already Defined'
#else
#	ifdef __SSC_MemoryLocking__
#		define   LOCK_MEMORY(address,size)   lock_os_memory( address, size )
#		define UNLOCK_MEMORY(address,size) unlock_os_memory( address, size )
#	else
#		define   LOCK_MEMORY(address,size)
#		define UNLOCK_MEMORY(address,size)
#	endif
#endif

namespace ssc::crypto_impl::ctr_v1 {

	void
	encrypt	(Input const & input) {
		using namespace std;

		OS_Map input_map, output_map;

		// Open input file
		input_map.os_file = open_existing_os_file( input.input_filename.c_str(), true );
		// Create output file
		output_map.os_file = create_os_file( input.output_filename.c_str() );
		// Determine input file size
		input_map.size = get_file_size( input_map.os_file );
		// The output file will be the size of the input file, plus the size of all CBC_V1 metadta.
		output_map.size = input_map.size + Metadata_Bytes;
		// Extend or shrink the output file to match calculated file size
		set_os_file_size( output_map.os_file, output_map.size );
		// Memory-Map the files
		map_file( input_map , true  );
		map_file( output_map, false );
		_CTIME_CONST(int) CSPRNG_Buffer_Bytes = CSPRNG_t::Minimum_Buffer_Size;
		_CTIME_CONST(int) CSPRNG_CTR_Shared_Bytes = (CSPRNG_Buffer_Bytes > CTR_t::Buffer_Bytes ? CSPRNG_Buffer_Bytes : CTR_t::Buffer_Bytes );
		_CTIME_CONST(int) Master_Secret_Bytes = (Block_Bytes * 2);
		_CTIME_CONST(int) Crypto_Buffer_Size = []() -> int {
			int size = 0;
			size += (Password_Buffer_Bytes * 2);
			size += Master_Secret_Bytes;
			size += Threefish_t::Buffer_Bytes;
			size +=       UBI_t::Buffer_Bytes;
			size += CSPRNG_CTR_Shared_Bytes;
			size += Supplement_Entropy_Buffer_Bytes;
			size += (size % sizeof(u64_t));
			return size;
		}();
		u8_t	crypto_buffer	[Crypto_Buffer_Size];

		static_assert (sizeof(crypto_buffer) == Crypto_Buffer_Size);

		LOCK_MEMORY( crypto_buffer, sizeof(crypto_buffer) );

		_CTIME_CONST(int) Password_Offset = 0;
		_CTIME_CONST(int) Password_Check_Offset = Password_Offset + Password_Buffer_Bytes;
		_CTIME_CONST(int) Master_Secret_Offset = Password_Check_Offset + Password_Buffer_Bytes;
		_CTIME_CONST(int) Threefish_Data_Offset = Master_Secret_Offset + Master_Secret_Bytes;
		_CTIME_CONST(int) UBI_Data_Offset = Threefish_Data_Offset + Threefish_t::Buffer_Bytes;
		_CTIME_CONST(int) CSPRNG_Data_Offset = UBI_Data_Offset + UBI_t::Buffer_Bytes;
		_CTIME_CONST(int) Entropy_Data_Offset = CSPRNG_Data_Offset + CSPRNG_Buffer_Bytes;

		_CTIME_CONST(int) CTR_Data_Offset = CSPRNG_Data_Offset;

		char	* const password = reinterpret_cast<char *>(crypto_buffer + Password_Offset);
		char	* const password_check = reinterpret_cast<char *>(crypto_buffer + Password_Check_Offset);
		u8_t	* const master_secret = (crypto_buffer + Master_Secret_Offset);
		u64_t	* const threefish_data = reinterpret_cast<u64_t *>(crypto_buffer + Threefish_Data_Offset);
		u8_t	* const ubi_data = (crypto_buffer + UBI_Data_Offset);
		u8_t	* const csprng_data = (crypto_buffer + CSPRNG_Data_Offset);
		u8_t	* const entropy_data = (crypto_buffer + Entropy_Data_Offset);

		Threefish_t	threefish{ threefish_data };
		UBI_t		ubi{ &threefish, ubi_data };
		Skein_t         skein{ &ubi };
		CSPRNG_t	csprng{ &skein, csprng_data, CSPRNG_Buffer_Bytes };

		int const password_length = obtain_password( password, password_check, Password_Prompt, Password_Reentry_Prompt, Password_Buffer_Bytes );
		zero_sensitive( password_check, Password_Buffer_Bytes );
		// Mix in additional entropy from the keyboard if specified
		if (input.supplement_os_entropy) {
			supplement_entropy( csprng, skein, entropy_data );
			zero_sensitive( entropy_data, Supplement_Entropy_Buffer_Bytes );
		}
		// Create a header
		CTR_V1_Header header;
		static_assert (sizeof(header.id) == sizeof(CTR_V1_ID));
		memcpy( header.id, CTR_V1_ID, sizeof(header.id) );
		header.total_size = static_cast<decltype(header.total_size)>(output_map.size);
		csprng.get( header.tweak      , sizeof(header.tweak)       );
		csprng.get( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
		csprng.get( header.ctr_nonce  , sizeof(header.ctr_nonce)   );
		zero_sensitive( csprng_data, CSPRNG_Buffer_Bytes );
		header.num_iter   = input.number_sspkdf_iterations;
		header.num_concat = input.number_sspkdf_concatenations;
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

			memcpy( out, header.ctr_nonce, sizeof(header.ctr_nonce) );
			out += sizeof(header.ctr_nonce);

			memcpy( out, &header.num_iter, sizeof(header.num_iter) );
			out += sizeof(header.num_iter);

			memcpy( out, &header.num_concat, sizeof(header.num_concat) );
			out += sizeof(header.num_concat);
		}

		static_assert (Master_Secret_Bytes == (Block_Bytes * 2));
		_CTIME_CONST(int) Key_Bytes = Block_Bytes;
		u8_t *confidentiality_key = master_secret;
		u8_t *authentication_key  = master_secret + Key_Bytes;
		// Write 512-bits of sspkdf keying material to the master_secret ptr.
		sspkdf( master_secret, skein, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		// Hash the 512-bits of sspkdf keying material into 1024 bits of key, for use in confidentialy and authenticity assurance.
		skein.hash( master_secret, master_secret, Key_Bytes, Master_Secret_Bytes );
		zero_sensitive( password, Password_Buffer_Bytes );


		{
			threefish.rekey( confidentiality_key, header.tweak );
			CTR_t ctr{ &threefish, (crypto_buffer + CTR_Data_Offset) };
			ctr.set_nonce( header.ctr_nonce );
			ctr.xorcrypt( out, input_map.ptr, input_map.size );
			out += input_map.size;
		}
		{
			// Create a 512-bit Message Authentication Code of the ciphertext, using the derived key and the ciphertext with Skein's native MAC
			// then append the MAC to the end of the ciphertext.
			skein.message_auth_code( out, output_map.ptr, authentication_key, output_map.size - MAC_Bytes, Key_Bytes, MAC_Bytes );
		}
		zero_sensitive( crypto_buffer, sizeof(crypto_buffer) );

		UNLOCK_MEMORY( crypto_buffer, sizeof(crypto_buffer) );

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
		// For now, assume the size of the output file will be the same size as the input file minus metadata.
		output_map.size = input_map.size - Metadata_Bytes;

		_CTIME_CONST(int) Minimum_Possible_File_Size = Metadata_Bytes + 1;

		if (input_map.size < Minimum_Possible_File_Size) {
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: Input file doesn't appear to be large enough to be a SSC_CTR_V1 encrypted file\n" );
		}
		// Set the output file to be `output_map.size` bytes.
		set_os_file_size( output_map.os_file, output_map.size );
		// Memory-map the input and output files.
		map_file( input_map , true  );
		map_file( output_map, false );
		// The `in` pointer is used for reading from the input files, and incremented as it's used to read.
		u8_t const *in = input_map.ptr;
		CTR_V1_Header header;
		// Copy all the fields of CBC_V2_Header_t from the memory-mapped input file into the header struct.
		{
			memcpy( header.id, in, sizeof(header.id) );
			in += sizeof(header.id);

			memcpy( &header.total_size, in, sizeof(header.total_size) );
			in += sizeof(header.total_size);

			memcpy( header.tweak, in, sizeof(header.tweak) );
			in += sizeof(header.tweak);

			memcpy( header.sspkdf_salt, in, sizeof(header.sspkdf_salt) );
			in += sizeof(header.sspkdf_salt);

			memcpy( header.ctr_nonce, in, sizeof(header.ctr_nonce) );
			in += sizeof(header.ctr_nonce);

			memcpy( &header.num_iter, in, sizeof(header.num_iter) );
			in += sizeof(header.num_iter);

			memcpy( &header.num_concat, in, sizeof(header.num_concat) );
			in += sizeof(header.num_concat);
		}
		static_assert (sizeof(header.id) == sizeof(CTR_V1_ID));
		if (memcmp( header.id, CTR_V1_ID, sizeof(CTR_V1_ID) ) != 0) {
			unmap_file( input_map );
			unmap_file( output_map );
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: The input file doesn't appear to be a SSC_CTR_V1 encrypted file.\n" );
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
		_CTIME_CONST(int)	Key_Bytes = Block_Bytes;
		_CTIME_CONST(int)	Master_Secret_Bytes = (Block_Bytes * 2);
		_CTIME_CONST(int)	UBI_CTR_Shared_Bytes = (UBI_t::Buffer_Bytes > CTR_t::Buffer_Bytes ? UBI_t::Buffer_Bytes : CTR_t::Buffer_Bytes);
		_CTIME_CONST(int)	Crypto_Buffer_Size = []() -> int {
			int size = 0;
			size += Password_Buffer_Bytes;
			size += Key_Bytes;
			size += Key_Bytes;
			size += Threefish_t::Buffer_Bytes;
			size += UBI_CTR_Shared_Bytes;
			size += (size % sizeof(u64_t));
			return size;
		}();

		_CTIME_CONST(int)	Password_Offset = 0;
		_CTIME_CONST(int)	Master_Secret_Offset = Password_Offset + Password_Buffer_Bytes;
		_CTIME_CONST(int)	Confidentiality_Key_Offset = Master_Secret_Offset;
		_CTIME_CONST(int)	Authenication_Key_Offset   = Confidentiality_Key_Offset + Key_Bytes;
		_CTIME_CONST(int)	Threefish_Data_Offset = Authenication_Key_Offset + Key_Bytes;
		_CTIME_CONST(int)	UBI_Data_Offset = Threefish_Data_Offset + Threefish_t::Buffer_Bytes;
		_CTIME_CONST(int)	CTR_Data_Offset = UBI_Data_Offset;

		u8_t	crypto_buffer [Crypto_Buffer_Size];

		LOCK_MEMORY( crypto_buffer, sizeof(crypto_buffer) );

		char	* const password = reinterpret_cast<char *>(crypto_buffer + Password_Offset);
		u8_t	* const master_secret = (crypto_buffer + Master_Secret_Offset);
		u8_t	* const confidentiality_key = (crypto_buffer + Confidentiality_Key_Offset);
		u8_t	* const authentication_key  = (crypto_buffer + Authenication_Key_Offset);
		u64_t	* const threefish_data = reinterpret_cast<u64_t *>(crypto_buffer + Threefish_Data_Offset);
		u8_t	* const ubi_data = (crypto_buffer + UBI_Data_Offset);

		Threefish_t	threefish{ threefish_data };
		UBI_t		ubi{ &threefish, ubi_data };
		Skein_t		skein{ &ubi };
		int password_length = obtain_password( password, Password_Prompt, Password_Buffer_Bytes );

		// Write 512-bits of sspkdf key material to the master_secret ptr.
		sspkdf( master_secret, skein, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		zero_sensitive( password, Password_Buffer_Bytes );
		{
			skein.hash( master_secret, master_secret, Key_Bytes, Master_Secret_Bytes );
		}


		{
			// Generate a MAC using the ciphertext and the derived key, and compare it to the MAC at the end of the input file.
			u8_t generated_mac [MAC_Bytes];
			{
				skein.message_auth_code( generated_mac,
						         input_map.ptr,
							 authentication_key,
							 input_map.size - MAC_Bytes,
							 Key_Bytes,
							 sizeof(generated_mac) );
				zero_sensitive( authentication_key, Key_Bytes );
			}
			if (memcmp( generated_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes) != 0) {
				zero_sensitive( crypto_buffer, sizeof(crypto_buffer) );

				UNLOCK_MEMORY( crypto_buffer, sizeof(crypto_buffer) );

				unmap_file( input_map );
				unmap_file( output_map );
				close_os_file( input_map.os_file );
				close_os_file( output_map.os_file );
				remove( output_filename );
				errx( "Error: Authentication failed.\n"
				      "Possibilities: Wrong password, the file is corrupted, or it has been somehow tampered with.\n" );
			}
		}
		{
			threefish.rekey( confidentiality_key, header.tweak );
			zero_sensitive( confidentiality_key, Key_Bytes );

			CTR_t	ctr{ &threefish, (crypto_buffer + CTR_Data_Offset) };
			ctr.set_nonce( header.ctr_nonce );
			ctr.xorcrypt( output_map.ptr, in, input_map.size - Metadata_Bytes );
		}
		zero_sensitive( crypto_buffer, sizeof(crypto_buffer) );

		UNLOCK_MEMORY( crypto_buffer, sizeof(crypto_buffer) );

		// Synchronize the output file.
		sync_map( output_map );
		// Unmap the memory-mapped input and output files.
		unmap_file( input_map );
		unmap_file( output_map );
		set_os_file_size( output_map.os_file, output_map.size );
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
		static constexpr auto const Minimum_Size = CTR_V1_Header::Total_Size + MAC_Bytes + 1;
		if (os_map.size < Minimum_Size) {
			close_os_file( os_map.os_file );
			errx( "File `%s` looks too small to be CTR_V1 encrypted\n", filename );
		}
		map_file( os_map, true );

		CTR_V1_Header header;
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

			memcpy( header.ctr_nonce, p, sizeof(header.ctr_nonce) );
			p += sizeof(header.ctr_nonce);

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
		fputs  (         "\nCTR Nonce                  : ", stdout );
		print_integral_buffer<u8_t>( header.ctr_nonce, sizeof(header.ctr_nonce) );
		fprintf( stdout, "\nNumber Iterations          : %u\n", header.num_iter );
		fprintf( stdout,   "Number Concatenations      : %u\n", header.num_concat );
		fputs(             "Message Authentication Code: ", stdout );
		print_integral_buffer<u8_t>( mac, sizeof(mac) );
		putchar( '\n' );
	}/* ! dump_header */
}/*namespace ssc::crypto_impl::ctr_v1*/
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
