#include "cbc_v2_f.hh"
#include "sspkdf.hh"

using namespace std;

#if    defined (LOCK_MEMORY) || defined (UNLOCK_MEMORY)
#	error 'Some MACRO we need was already defined'
#endif

#ifdef __SSC_MemoryLocking__
#	define LOCK_MEMORY(address,size)	lock_os_memory( address, size )
#	define UNLOCK_MEMORY(address,size)	unlock_os_memory( address, size )
#else
#	define LOCK_MEMORY(none_0,none_1)
#	define UNLOCK_MEMORY(non_0,none_1)
#endif

namespace ssc::crypto_impl::cbc_v2
{
	static u64_t calculate_encrypted_size (u64_t const pre_encryption_size)
	{
		u64_t s = pre_encryption_size;
		if( s < Block_Bytes )
			s = Block_Bytes;
		else
			s += (Block_Bytes - (s % Block_Bytes));
		return s + Metadata_Bytes;
	}
	static void cleanup_map (OS_Map &os_map)
	{
		unmap_file( os_map );
		close_os_file( os_map.os_file );
	}
	void encrypt (SSPKDF_Input &sspkdf_input,
		      OS_Map       &input_map,
		      OS_Map       &output_map)
	{
		// The passed in input_map has all its parameters in order, but the output_map has only its os_file set.
		output_map.size = calculate_encrypted_size( input_map.size );
		set_os_file_size( output_map.os_file, output_map.size );
		map_file( output_map, false );

		struct {
			typename CBC_f::Data    cbc_data;
			u64_t                   key_buffer [Threefish_f::External_Key_Words];
			typename UBI_f::Data    ubi_data;
			typename CSPRNG_f::Data csprng_data;
			u8_t                    first_password  [Password_Buffer_Bytes];
			u8_t                    second_password [Password_Buffer_Bytes];
			u8_t                    entropy_data    [Supplement_Entropy_Buffer_Bytes];
		} crypto_object;
		struct {
			              u64_t  tweak       [Threefish_f::Tweak_Words];
	                alignas(u64_t) u8_t  cbc_iv      [Threefish_f::Block_Bytes];
	                alignas(u64_t) u8_t  sspkdf_salt [Salt_Bytes];
		} public_object;

		LOCK_MEMORY ((&crypto_object),sizeof(crypto_object));

		int password_length;
		u8_t *out = output_map.ptr;
		{
			password_length = obtain_password<Password_Buffer_Bytes>( crypto_object.first_password,
										  crypto_object.second_password,
										  Password_Prompt,
										  Password_Reentry_Prompt );
			zero_sensitive( crypto_object.second_password, Password_Buffer_Bytes );
		}
		CSPRNG_f::initialize_seed( &crypto_object.csprng_data );
		if( sspkdf_input.supplement_os_entropy ) {
			supplement_entropy( &crypto_object.csprng_data,
					    crypto_object.entropy_data,
					    crypto_object.entropy_data + Block_Bytes );
			zero_sensitive( crypto_object.entropy_data, Supplement_Entropy_Buffer_Bytes );
		}
		{
			CSPRNG_f::get( &crypto_object.csprng_data,
				       reinterpret_cast<u8_t*>(public_object.tweak),
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
			*(reinterpret_cast<u64_t*>(out)) = output_map.size; // Total size.
			out += sizeof(u64_t);
			memcpy( out, public_object.tweak, Tweak_Bytes );
			out += Tweak_Bytes;
			memcpy( out, public_object.sspkdf_salt, sizeof(public_object.sspkdf_salt) ); // SSPKDF Salt.
			out += sizeof(public_object.sspkdf_salt);
			memcpy( out, public_object.cbc_iv, sizeof(public_object.cbc_iv) ); // CBC IV.
			out += sizeof(public_object.cbc_iv);
			*(reinterpret_cast<u32_t*>(out)) = sspkdf_input.number_iterations; // SSPKDF Iterations.
			out += sizeof(u32_t);
			*(reinterpret_cast<u32_t*>(out)) = sspkdf_input.number_concatenations; // SSPKDF Concatenations.
			out += sizeof(u32_t);
		}
		sspkdf( &crypto_object.ubi_data,
		        reinterpret_cast<u8_t*>(crypto_object.key_buffer),
			crypto_object.first_password,
			password_length,
			public_object.sspkdf_salt,
			sspkdf_input.number_iterations,
			sspkdf_input.number_concatenations );
		zero_sensitive( crypto_object.first_password, sizeof(crypto_object.first_password) );
		{
			Threefish_f::rekey( &(crypto_object.cbc_data.threefish_data),
					    crypto_object.key_buffer,
					    public_object.tweak );
			out += CBC_f::encrypt( &(crypto_object.cbc_data),
					       out,
					       input_map.ptr,
					       public_object.cbc_iv,
					       input_map.size );
			zero_sensitive( &(crypto_object.cbc_data), sizeof(crypto_object.cbc_data) );
		}
		{
			Skein_f::mac( &(crypto_object.ubi_data),
				      out, // bytes out
				      output_map.ptr, // bytes in
				      reinterpret_cast<u8_t*>(crypto_object.key_buffer), // key in
				      Block_Bytes, // number bytes in
				      MAC_Bytes ); // num bytes out
		}
		zero_sensitive( &(crypto_object), sizeof(crypto_object) );

		UNLOCK_MEMORY ((&crypto_object),sizeof(crypto_object));

		sync_map( output_map );
		cleanup_map( output_map );
		cleanup_map( input_map );
	}
	void decrypt (OS_Map &input_map,
		      OS_Map &output_map,
		      char const *output_filename)
	{
		using namespace std;
		output_map.size = input_map.size;
		_CTIME_CONST (int) Minimum_Possible_File_Size = Metadata_Bytes + Block_Bytes + MAC_Bytes;
		if( input_map.size < Minimum_Possible_File_Size ) {
			close_os_file( output_map.os_file );
			remove( output_filename );
			unmap_file( input_map );
			close_os_file( input_map.os_file );
			errx( "Error: Input file doesn't appear to be large enough to be a 3CRYPT_CBC_V2 encrypted file\n" );
		}
		set_os_file_size( output_map.os_file, output_map.size );
		map_file( output_map, false );
		u8_t const *in = input_map.ptr;
		struct {
			              u64_t tweak       [Threefish_f::Tweak_Words];
			alignas(u64_t) u8_t sspkdf_salt [Salt_Bytes];
			alignas(u64_t) u8_t cbc_iv      [Block_Bytes];
			               char header_id   [sizeof(CBC_V2_ID)];
			              u64_t header_size;
				      u32_t num_iter;
				      u32_t num_concat;
			
		} data;
		// Copy all the fields of a CBC_V2 header from the memory-mapped input file into the header struct.
		{
			memcpy( data.header_id, in, sizeof(data.header_id) );
			in += sizeof(data.header_id);
			data.header_size = *(reinterpret_cast<u64_t*>(in));
			in += sizeof(u64_t);
			memcpy( data.tweak, in, Tweak_Bytes );
			in += Tweak_Bytes;
			memcpy( data.sspkdf_salt, in, sizeof(data.sspkdf_salt) );
			in += sizeof(data.sspkdf_salt);
			memcpy( data.cbc_iv, in, sizeof(data.cbc_iv) );
			in += sizeof(data.cbc_iv);
			data.num_iter = *(reinterpret_cast<u32_t*>(in));
			in += sizeof(u32_t);
			data.num_concat = *(reinterpret_cast<u32_t*>(in));
			in += sizeof(u32_t);
		}
		if( memcmp( data.header_id, CBC_V2_ID, sizeof(CBC_V2_ID) ) != 0 ) {
			unmap_file( input_map );
			unmap_file( output_map );
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: Input file size (%zu) does not equal file size in the file header of the input file (%zu)\n",
			      input_map.size, data.header_size );
		}
		struct {
			typename CBC_f::Data    cbc_data;
			u64_t                   key_buffer [Threefish_f::External_Key_Buffer_Words];
			typename UBI_f::Data    ubi_data;
			u8_t                    password   [Password_Buffer_Bytes];
		} crypto;
		
		LOCK_MEMORY (&crypto,sizeof(crypto));

		int password_length = obtain_password<Password_Buffer_Bytes>( crypto.password, Password_Prompt );
		sspkdf( &crypto.ubi_data,
			reinterpret_cast<u8_t*>(crypto.key_buffer),
			crypto.password,
			password_length,
			data.sspkdf_salt,
			data.num_iter,
			data.num_concat );
		zero_sensitive( crypto.password, sizeof(crypto.password) );
		{
			alignas(u64_t) u8_t generated_mac [MAC_Bytes];
			{
				Skein_f::mac( &crypto.ubi_data,
					      generated_mac,
					      input_map.ptr,
					      reinterpret_cast<u8_t*>(crypto.key_buffer),
					      sizeof(generated_mac),
					      input_map.size - MAC_Bytes );
			}
			if( memcmp( generated_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes) != 0 ) {
				zero_sensitive( &crypto, sizeof(crypto) );

				UNLOCK_MEMORY (&crypto, sizeof(crypto));

				unmap_file( input_map );
				unmap_file( output_map );
				close_os_file( input_map.os_file );
				close_os_file( output_map.os_file );
				remove( output_filename );
				errx( "Error: Authentication failed.\n"
				      "Possibilities: Wrong password, the file is corrupted, or it has been tampered with.\n" );
			}
		}
		u64_t plaintext_size;
		{
			Threefish_f::rekey( &(crypto.cbc_data.threefish_data),
					    crypto.key_buffer,
					    data.tweak );
			plaintext_size = CBC_f::decrypt( &(crypto.cbc_data),
					                 output_map.ptr,
							 in,
							 data.cbc_iv,
							 input_map.size - Metadata_Bytes );
		}
		zero_sensitive( &crypto, sizeof(crypto) );

		UNLOCK_MEMORY (&crypto,sizeof(crypto));

		sync_map( output_map );
		unmap_file( input_map );
		unmap_file( output_map );
		set_os_file_size( output_map.os_file, plaintext_size );
		close_os_file( input_map.os_file );
		close_os_file( output_map.os_file );

	}

	void dump_header (OS_Map &os_map,
			  char const *filename)
	{
		using std::memcpy, std::fprintf, std::fputs, std::putchar, std::exit;

		_CTIME_CONST (int) Minimum_Size = Metadata_Bytes + Block_Bytes;
		if (os_map.size < Minimum_Size) {
			unmap_file( os_map );
			close_os_file( os_map.os_file );
			errx( "File `%s` looks too small to be CBC_V2 encrypted\n", filename );
		}

		struct {
			char id [sizeof(CBC_V2_ID)];
			u64_t total_size;
			u8_t  tweak  [Tweak_Bytes];
			u8_t  salt   [Salt_Bytes];
			u8_t  cbc_iv [Block_Bytes];
			u32_t num_iter;
			u32_t num_concat;
		} header;
		u8_t mac [MAC_Bytes];
		{
			u8_t const *p = os_map.ptr;

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

}
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
