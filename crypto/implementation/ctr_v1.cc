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
#	error "This is experimental."
#endif

#include <cstdio>

#include <ssc/crypto/implementation/ctr_v1.hh>

#include <ssc/crypto/sspkdf.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/print.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/files/files.hh>
#include <ssc/files/os_map.hh>
#include <ssc/interface/terminal.hh>
#include <ssc/memory/os_memory_locking.hh>

namespace ssc::crypto_impl::ctr_v1 {

	void
	encrypt	(Input const & input) {
		using namespace std;

		CSPRNG_t csprng;
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
		// Get the password
		char password [Password_Buffer_Bytes];
#ifdef __SSC_MemoryLocking__
		lock_os_memory( password, sizeof(password) );
#endif
		int password_length = obtain_password( password, Password_Prompt, Password_Reentry_Prompt, sizeof(password) );
		// Mix in additional entropy from the keyboard if specified
		if (input.supplement_os_entropy)
			supplement_entropy( csprng );
		// Create a header
		CTR_V1_Header header;
		static_assert (sizeof(header.id) == sizeof(CTR_V1_ID));
		memcpy( header.id, CTR_V1_ID, sizeof(header.id) );
		header.total_size = static_cast<decltype(header.total_size)>(output_map.size);
		csprng.get( header.tweak      , sizeof(header.tweak)       );
		csprng.get( header.sspkdf_salt, sizeof(header.sspkdf_salt) );
		csprng.get( header.ctr_nonce  , sizeof(header.ctr_nonce)   );
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
		// Generate 1024 pseudorandom bits using sspkdf.
		u8_t master_secret [Block_Bytes * 2];
#ifdef __SSC_MemoryLocking__
		lock_os_memory( master_secret, sizeof(master_secret) );
#endif
		u8_t *confidentiality_key = master_secret;
		u8_t *authentication_key  = master_secret + Block_Bytes;
		sspkdf( master_secret, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		{
			Skein_t skein;
			skein.hash( master_secret, master_secret, Block_Bytes, sizeof(master_secret) );
		}
#if 0
		// Generate a 512-bit symmetric key using the password we got earlier as input
		u8_t derived_key [Block_Bytes];
#ifdef __SSC_MemoryLocking__
		lock_os_memory( derived_key, sizeof(derived_key) );
#endif
		sspkdf( derived_key, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
#endif
		// Securely zero over the password buffer after we've used it to generate the symmetric key
		zero_sensitive( password, sizeof(password) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( password, sizeof(password) );
#endif
		{
#if 0
			// Encrypt the input file, writing the ciphertext into the memory-mapped output file
			Threefish_t threefish{ derived_key, header.tweak };
			CTR_t ctr{ &threefish, header.ctr_nonce };
			ctr.xorcrypt( out, input_map.ptr, input_map.size );
			out += input_map.size;
#endif
			CTR_t ctr{ header.ctr_nonce, confidentiality_key, header.tweak };
			ctr.xorcrypt( out, input_map.ptr, input_map.size );
			out += input_map.size;
		}
		{
			// Create a 512-bit Message Authentication Code of the ciphertext, using the derived key and the ciphertext with Skein's native MAC
			// then append the MAC to the end of the ciphertext.
			Skein_t skein;
			skein.message_auth_code( out, output_map.ptr, authentication_key, output_map.size - MAC_Bytes, Block_Bytes, MAC_Bytes );
		}
#if 0
		// Securely zero over the derived key
		zero_sensitive( derived_key, sizeof(derived_key) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( derived_key, sizeof(derived_key) );
#endif
#endif
		zero_sensitive( master_secret, sizeof(master_secret) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( master_secret, sizeof(master_secret) );
#endif
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
		static constexpr auto const Minimum_Possible_File_Size = Metadata_Bytes + 1;
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
		// Get the password
		char password [Password_Buffer_Bytes] = { 0 };
#ifdef __SSC_MemoryLocking__
		lock_os_memory( password, sizeof(password) );
#endif
		int  password_length = obtain_password( password, Password_Prompt, Max_Password_Chars );
#if 0
#ifdef __SSC_MemoryLocking__
		lock_os_memory( password, sizeof(password) );
#endif
		{
			Terminal term;
			password_length = term.get_pw( password, Max_Password_Length, 1, Password_Prompt );
		}
#endif
		u8_t master_secret [Block_Bytes * 2];
		u8_t *confidentiality_key = master_secret;
		u8_t *authentication_key  = master_secret + Block_Bytes;
#ifdef __SSC_MemoryLocking__
		lock_os_memory( master_secret, sizeof(master_secret) );
#endif
		sspkdf( master_secret, password, password_length, header.sspkdf_salt, header.num_iter, header.num_concat );
		{
			Skein_t skein;
			skein.hash( master_secret, master_secret, Block_Bytes, sizeof(master_secret) );
		}
		// Securely zero over the password now that we have the derived key.
		zero_sensitive( password, sizeof(password) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( password, sizeof(password) );
#endif
		{
			// Generate a MAC using the ciphertext and the derived key, and compare it to the MAC at the end of the input file.
			u8_t generated_mac [MAC_Bytes];
			{
				Skein_t skein;
				skein.message_auth_code( generated_mac,
						         input_map.ptr,
							 authentication_key,
							 input_map.size - MAC_Bytes,
							 Block_Bytes,
							 sizeof(generated_mac) );
			}
			if (memcmp( generated_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes) != 0) {
				zero_sensitive( master_secret, sizeof(master_secret) );
#ifdef __SSC_MemoryLocking__
				unlock_os_memory( master_secret, sizeof(master_secret) );
#endif
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
			CTR_t ctr{ header.ctr_nonce, confidentiality_key, header.tweak };
			ctr.xorcrypt( output_map.ptr, in, input_map.size - Metadata_Bytes );
#if 0
			// Decrypt the input file's ciphertext into the output file, recording the number of bytes of plaintext in `plaintext_size`.
			Threefish_t threefish{ derived_key, header.tweak };
			CTR_t ctr{ &threefish, header.ctr_nonce };
			// Securely zero over the derived key now that we're done with it.
			zero_sensitive( derived_key, sizeof(derived_key) );
#ifdef __SSC_MemoryLocking__
			unlock_os_memory( derived_key, sizeof(derived_key) );
#endif
			ctr.xorcrypt( output_map.ptr, in, input_map.size - Metadata_Bytes );
#endif
		}
		zero_sensitive( master_secret, sizeof(master_secret) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( master_secret, sizeof(master_secret) );
#endif
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
