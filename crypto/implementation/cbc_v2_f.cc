/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include "cbc_v2_f.hh"
#include "sspkdf.hh"

using namespace std;

#if    defined (LOCK_MEMORY_) || defined (UNLOCK_MEMORY_)
#	error 'Some MACRO we need was already defined'
#endif

#ifdef SHIM_FEATURE_MEMORYLOCKING
#	define LOCK_MEMORY_(address, size)	shim_lock_memory( address, size )
#	define UNLOCK_MEMORY_(address, size)	shim_unlock_memory( address, size )
#else
#	define LOCK_MEMORY_(address, size)
#	define UNLOCK_MEMORY_(address, size)
#endif

namespace ssc::crypto_impl::cbc_v2 {

	static uint64_t
	calculate_encrypted_size (uint64_t const pre_encryption_size) {
		uint64_t s = pre_encryption_size;
		if( s < Block_Bytes )
			s = Block_Bytes;
		else
			s += (Block_Bytes - (s % Block_Bytes));
		return s + Metadata_Bytes;
	}

	static void
	cleanup_memory (Shim_Map &shim_map) {
		shim_unmap_memory( &shim_map );
		shim_close_file( shim_map.shim_file );
	}

	void encrypt (SSPKDF_Input & SHIM_RESTRICT sspkdf_input,
		      Shim_Map &     SHIM_RESTRICT input_map,
		      Shim_Map &     SHIM_RESTRICT output_map)
	{
		// The passed in input_map has all its parameters in order, but the output_map has only its os_file set.
		output_map.size = calculate_encrypted_size( input_map.size );
		shim_set_file_size( output_map.shim_file, output_map.size );
		shim_map_memory( &output_map, false );

		struct {
			typename CBC_f::Data    cbc_data;
			uint64_t                key_buffer [Threefish_f::External_Key_Words];
			typename UBI_f::Data    ubi_data;
			typename CSPRNG_f::Data csprng_data;
			uint8_t                 first_password  [Password_Buffer_Bytes];
			uint8_t                 second_password [Password_Buffer_Bytes];
			uint8_t                 entropy_data    [Supplement_Entropy_Buffer_Bytes];
		} crypto_object;
		struct {
			                 uint64_t  tweak       [Threefish_f::External_Tweak_Words];
	                alignas(uint64_t) uint8_t  cbc_iv      [Threefish_f::Block_Bytes];
	                alignas(uint64_t) uint8_t  sspkdf_salt [Salt_Bytes];
		} public_object;

		LOCK_MEMORY_ (&crypto_object, sizeof(crypto_object));

		int password_length;
		uint8_t *out = output_map.ptr;
		{
			Terminal_UI_f::init();
			password_length = Terminal_UI_f::obtain_password( crypto_object.first_password,
					                                  crypto_object.second_password,
									  Password_Prompt,
									  Password_Reentry_Prompt );
			shim_set_file_size( crypto_object.second_password, Password_Buffer_Bytes );
		}
		CSPRNG_f::initialize_seed( &crypto_object.csprng_data );
		if( sspkdf_input.supplement_os_entropy ) {
			supplement_entropy( &crypto_object.csprng_data,
					    crypto_object.entropy_data,
					    crypto_object.entropy_data + Block_Bytes );
			shim_secure_zero( crypto_object.entropy_data, Supplement_Entropy_Buffer_Bytes );
		}
		Terminal_UI_f::end();
		{
			CSPRNG_f::get( &crypto_object.csprng_data,
				       reinterpret_cast<uint8_t*>(public_object.tweak),
				       Tweak_Bytes );
			CSPRNG_f::get( &crypto_object.csprng_data,
					public_object.cbc_iv,
					sizeof(public_object.cbc_iv) );
			CSPRNG_f::get( &crypto_object.csprng_data,
				       public_object.sspkdf_salt,
				       sizeof(public_object.sspkdf_salt) );
		}
		{
			memcpy( out, CBC_V2_ID, sizeof(CBC_V2_ID) ); // Header ID.
			out += sizeof(CBC_V2_ID);
			std::memcpy( out, &output_map.size, sizeof(output_map.size) );
			out += sizeof(uint64_t);
			memcpy( out, public_object.tweak, Tweak_Bytes );
			out += Tweak_Bytes;
			memcpy( out, public_object.sspkdf_salt, sizeof(public_object.sspkdf_salt) ); // SSPKDF Salt.
			out += sizeof(public_object.sspkdf_salt);
			memcpy( out, public_object.cbc_iv, sizeof(public_object.cbc_iv) ); // CBC IV.
			out += sizeof(public_object.cbc_iv);
			std::memcpy( out, &sspkdf_input.number_iterations, sizeof(sspkdf_input.number_iterations) );
			out += sizeof(uint32_t);
			std::memcpy( out, &sspkdf_input.number_concatenations, sizeof(sspkdf_input.number_concatenations) );
		}
		sspkdf( &crypto_object.ubi_data,
		        reinterpret_cast<uint8_t*>(crypto_object.key_buffer),
			crypto_object.first_password,
			password_length,
			public_object.sspkdf_salt,
			sspkdf_input.number_iterations,
			sspkdf_input.number_concatenations );
		shim_secure_zero( crypto_object.first_password, sizeof(crypto_object.first_password) );
		{
			Threefish_f::rekey( &crypto_object.cbc_data.threefish_data,
					    crypto_object.key_buffer,
					    public_object.tweak );
			out += CBC_f::encrypt( &crypto_object.cbc_data,
					       out,
					       input_map.ptr,
					       public_object.cbc_iv,
					       input_map.size );
			shim_secure_zero( &crypto_object.cbc_data, sizeof(crypto_object.cbc_data) );
		}
		{
			Skein_f::mac( &crypto_object.ubi_data,
				      out, // bytes out
				      output_map.ptr, // bytes in
				      reinterpret_cast<uint8_t*>(crypto_object.key_buffer), // key in
				      MAC_Bytes, // number bytes out
				      output_map.size - MAC_Bytes); // num bytes in
		}
		shim_secure_zero( &crypto_object, sizeof(crypto_object) );

		UNLOCK_MEMORY_ (&crypto_object, sizeof(crypto_object));

		shim_sync_map( &output_map );
		cleanup_map( output_map );
		cleanup_map( input_map );
	}
	void
	decrypt (Shim_Map &   SHIM_RESTRICT input_map,
		 Shim_Map &   SHIM_RESTRICT output_map,
		 char const * SHIM_RESTRICT output_filename)
	{
		using namespace std;

		output_map.size = input_map.size - Metadata_Bytes;

		static constexpr int Minimum_Possible_File_Size = Metadata_Bytes + Block_Bytes; 
		if( input_map.size < Minimum_Possible_File_Size ) {
			shim_close_file( output_map.shim_file );
			remove( output_filename );
			shim_unmap_memory( &input_map );
			shim_close_file( input_map.shim_file );
			SHIM_ERRX ("Error: Input file doesn't appear to be large enough to be a 3CRYPT_CBC_V2 encrypted file\n");
		}
		shim_close_file( output_map.shim_file, output_map.size );
		shim_map_memory( &output_map, false );
		uint8_t const *in = input_map.ptr;
		struct {
			                  uint64_t tweak      [Threefish_f::Tweak_Words];
			alignas(uint64_t) uint8_t sspkdf_salt [Salt_Bytes];
			alignas(uint64_t) uint8_t cbc_iv      [Block_Bytes];
			                  char    header_id   [sizeof(CBC_V2_ID)];
			                  uint64_t header_size;
				          uint32_t num_iter;
				          uint32_t num_concat;
			
		} data;
		// Copy all the fields of a CBC_V2 header from the memory-mapped input file into the header struct.
		{
			memcpy( data.header_id, in, sizeof(data.header_id) );
			in += sizeof(data.header_id);
			memcpy( &data.header_size, in, sizeof(data.header_size) );
			in += sizeof(data.header_size);
			memcpy( data.tweak, in, Tweak_Bytes );
			in += Tweak_Bytes;
			memcpy( data.sspkdf_salt, in, sizeof(data.sspkdf_salt) );
			in += sizeof(data.sspkdf_salt);
			memcpy( data.cbc_iv, in, sizeof(data.cbc_iv) );
			in += sizeof(data.cbc_iv);
			memcpy( &data.num_iter  , in, sizeof(uint32_t) );
			in += sizeof(uint32_t);
			memcpy( &data.num_concat, in, sizeof(uint32_t) );
			in += sizeof(uint32_t);
		}
		if( shim_ctime_memcmp( data.header_id, CBC_V2_ID, sizeof(CBC_V2_ID) ) != 0 ) {
			shim_unmap_memory( &input_map );
			shim_unmap_memory( &output_map );
			shim_close_file( input_map.shim_file );
			shim_close_file( output_map.shim_file );
			remove( output_filename );
			SHIM_ERRX ("Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n",
			           input_map.size, data.header_size);
		}
		struct {
			typename CBC_f::Data    cbc_data;
			uint64_t                key_buffer [Threefish_f::External_Key_Words];
			typename UBI_f::Data    ubi_data;
			uint8_t                 password   [Password_Buffer_Bytes];
		} crypto;
		
		LOCK_MEMORY_ (&crypto, sizeof(crypto));

		Terminal_UI_f::init();
		int password_length = Terminal_UI_f::obtain_password( crypto.password, Password_Prompt );
		Terminal_UI_f::end();
		sspkdf( &crypto.ubi_data,
			reinterpret_cast<uint8_t*>(crypto.key_buffer),
			crypto.password,
			password_length,
			data.sspkdf_salt,
			data.num_iter,
			data.num_concat );
		shim_secure_zero( crypto.password, sizeof(crypto.password) );
		{
			alignas(uint64_t) uint8_t generated_mac [MAC_Bytes];
			{
				Skein_f::mac( &crypto.ubi_data,
					      generated_mac,
					      input_map.ptr,
					      reinterpret_cast<uint8_t*>(crypto.key_buffer),
					      sizeof(generated_mac),
					      input_map.size - MAC_Bytes );
			}
			if( shim_ctime_memcmp( generated_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes ) != 0 ) {
				shim_secure_zero( &crypto, sizeof(crypto) );

				UNLOCK_MEMORY_ (&crypto, sizeof(crypto));

				shim_unmap_memory( &input_map );
				shim_unmap_memory( &output_map );
				shim_close_file( input_map.shim_file );
				shim_close_file( output_map.shim_file );
				remove( output_filename );
				SHIM_ERRX ("Error: Authentication failed.\n"
				      	   "Possibilities: Wrong password, the file is corrupted, or it has been tampered with.\n");
			}
		}
		uint64_t plaintext_size;
		{
			Threefish_f::rekey( &crypto.cbc_data.threefish_data,
					    crypto.key_buffer,
					    data.tweak );
			plaintext_size = CBC_f::decrypt( &crypto.cbc_data,
					                 output_map.ptr,
							 in,
							 data.cbc_iv,
							 input_map.size - Metadata_Bytes );
		}
		shim_secure_zero( &crypto, sizeof(crypto) );

		UNLOCK_MEMORY_ (&crypto, sizeof(crypto));

		shim_sync_map( &output_map );
		shim_unmap_memory( &input_map );
		shim_unmap_memory( &output_map );
		shim_set_file_size( output_map.shim_file, plaintext_size );
		shim_close_file( input_map.shim_file );
		shim_close_file( output_map.shim_file );
	}

	void
	dump_header (Shim_Map &   SHIM_RESTRICT shim_map,
		     char const * SHIM_RESTRICT filename)
	{
		using std::memcpy, std::fprintf, std::fputs, std::putchar, std::exit;

		static constexpr int Minimum_Size = Metadata_Bytes + Block_Bytes;
		if (shim_map.size < Minimum_Size) {
			shim_unmap_memory( &shim_map );
			shim_close_file( shim_map.shim_file );
			SHIM_ERRX ("File %s looks too small to be CBC_V2 encrypted\n", filename );
		}

		struct {
			char id [sizeof(CBC_V2_ID)];
			uint64_t total_size;
			uint8_t  tweak  [Tweak_Bytes];
			uint8_t  salt   [Salt_Bytes];
			uint8_t  cbc_iv [Block_Bytes];
			uint32_t num_iter;
			uint32_t num_concat;
		} header;
		uint8_t mac [MAC_Bytes];
		{
			uint8_t const *p = shim_map.ptr;

			memcpy( header.id, p, sizeof(header.id) );
			p += sizeof(header.id);

			memcpy( &header.total_size, p, sizeof(header.total_size) );
			p += sizeof(header.total_size);

			memcpy( header.tweak, p, sizeof(header.tweak) );
			p += sizeof(header.tweak);

			memcpy( header.salt, p, sizeof(header.salt) );
			p += sizeof(header.salt);

			memcpy( header.cbc_iv, p, sizeof(header.cbc_iv) );
			p += sizeof(header.cbc_iv);

			memcpy( &header.num_iter, p, sizeof(header.num_iter) );
			p += sizeof(header.num_iter);

			memcpy( &header.num_concat, p, sizeof(header.num_concat) );

			p = shim_map.ptr + shim_map.size - MAC_Bytes;
			memcpy( mac, p, sizeof(mac) );
		}
		shim_unmap_memory( &shim_map );
		shim_close_file( shim_map.shim_file );

		fprintf( stdout,   "File Header ID             : %s\n", header.id );
		fprintf( stdout,   "File Size                  : %zu\n", header.total_size );
		fputs  (           "Threefish Tweak            : ", stdout );
		shim_print_byte_buffer( header.tweak, sizeof(header.tweak) );
		fputs  (         "\nSSPKDF Salt                : ", stdout );
		shim_print_byte_buffer( header.salt, sizeof(header.salt) );
		fputs  (         "\nCBC Initialization Vector  : ", stdout );
		shim_print_byte_buffer( header.cbc_iv, sizeof(header.cbc_iv) );
		fprintf( stdout, "\nNumber Iterations          : %u\n", header.num_iter );
		fprintf( stdout,   "Number Concatenations      : %u\n", header.num_concat );
		fputs(             "Message Authentication Code: ", stdout );
		shim_print_byte_buffer( mac, sizeof(mac) );
		putchar( '\n' );
	}/* ! dump_header */

}
#undef UNLOCK_MEMORY_
#undef LOCK_MEMORY_
