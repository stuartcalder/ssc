#include "dragonfly_v1.hh"
using namespace std;

#if    defined (LOCK_MEMORY) || defined (UNLOCK_MEMORY)
#       error 'Some MACRO we need was already defined'
#endif

#ifdef __SSC_MemoryLocking__
#       define LOCK_MEMORY(address,size)	  lock_os_memory( address, size )
#       define UNLOCK_MEMORY(address,size)	unlock_os_memory( address, size )
#else
#       define LOCK_MEMORY(none_0,none_1)
#       define UNLOCK_MEMORY(non_0,none_1)
#endif

namespace ssc::crypto_impl::dragonfly_v1
{
	void encrypt (Catena_Input const &catena_input,
		      OS_Map             &input_map,
		      OS_Map             &output_map,
		      char const         *output_filename)
	{
		{// Setup the output map.
			output_map.size = input_map.size + Visible_Metadata_Bytes;
			set_os_file_size( output_map.os_file, output_map.size );
			map_file( output_map, false );
		}

		static_assert (Block_Bytes == Threefish_f::Block_Bytes);
		struct {
			CTR_Data_t              ctr_data;
			union {
				typename Catena_Strong_f::Data strong;
				typename Catena_Safe_f::Data   safe;
			} catena;
			u64_t                   enc_key         [Threefish_f::External_Key_Words];
			alignas(u64_t) u8_t     auth_key        [Threefish_f::Block_Bytes];
			typename UBI_f::Data    ubi_data;
			u8_t                    first_password  [Password_Buffer_Bytes];
			u8_t                    second_password [Password_Buffer_Bytes];
			typename CSPRNG_f::Data csprng_data;
			u8_t                    entropy_data    [Supplement_Entropy_Buffer_Bytes];
			alignas(u64_t) u8_t    hash_output      [Block_Bytes * 2];

		} secret;
		struct {
			u64_t               tf_tweak    [Threefish_f::External_Tweak_Words];
			alignas(u64_t) u8_t ctr_nonce   [CTR_f::Nonce_Bytes];
			alignas(u64_t) u8_t catena_salt [Salt_Bytes];
		} pub;

		LOCK_MEMORY (&secret,sizeof(secret));

		int password_size;

		{// Obtain the password.
			password_size = obtain_password<Password_Buffer_Bytes>( secret.first_password,
					                                        secret.second_password,
										Password_Prompt,
										Password_Reentry_Prompt );
			zero_sensitive( secret.second_password, Password_Buffer_Bytes );
		}
		// Initialize the random number generator.
		CSPRNG_f::initialize_seed( &secret.csprng_data );
		if( catena_input.supplement_os_entropy ) { // Supplement the RNG's entropy if specified to do so.
			supplement_entropy( &secret.csprng_data,
					    secret.entropy_data,
					    secret.entropy_data + Block_Bytes );
			zero_sensitive( secret.entropy_data, sizeof(secret.entropy_data) );
		}
		{// 3 calls to the RNG to generate the tweak, nonce, and salt.
			CSPRNG_f::get( &secret.csprng_data,
				       reinterpret_cast<u8_t*>(pub.tf_tweak),
				       Tweak_Bytes );
			CSPRNG_f::get( &secret.csprng_data,
				       pub.ctr_nonce,
				       sizeof(pub.ctr_nonce) );
			CSPRNG_f::get( &secret.csprng_data,
				       pub.catena_salt,
				       sizeof(pub.catena_salt) );
			zero_sensitive( &secret.csprng_data, sizeof(secret.csprng_data) );
		}
		{
			// Generate the catena output, that we will then hash into encryption and authentication keys.
			if( !catena_input.use_phi ) {
				// Copy the salt in.
				memcpy( secret.catena.safe.salt,
					pub.catena_salt,
					sizeof(pub.catena_salt) );
				auto r = Catena_Safe_f::call( &(secret.catena.safe),
						              secret.hash_output,
						              secret.first_password,
						              password_size,
						              catena_input.g_low,
						              catena_input.g_high,
						              catena_input.lambda );
				if( r != Catena_Safe_f::Return_E::Success ) {
					zero_sensitive( &secret, sizeof(secret) );
					UNLOCK_MEMORY (&secret,sizeof(secret));
					unmap_file( output_map );
					unmap_file( input_map  );
					close_os_file( output_map.os_file );
					close_os_file( input_map.os_file  );
					remove( output_filename );
					errx( "Error: Catena_Safe_f failed with error code %d...\n"
					      "Allocating too much memory?\n", static_cast<int>(r) );
				}
				zero_sensitive( &(secret.catena.safe), sizeof(secret.catena.safe) );
			} else {
				// Copy the salt in.
				memcpy( secret.catena.strong.salt,
				        pub.catena_salt,
					sizeof(pub.catena_salt) );
				auto r = Catena_Strong_f::call( &(secret.catena.strong),
					  	                secret.hash_output,
						                secret.first_password,
						                password_size,
						                catena_input.g_low,
						                catena_input.g_high,
						                catena_input.lambda );
				if( r != Catena_Strong_f::Return_E::Success ) {
					zero_sensitive( &secret, sizeof(secret) );
					UNLOCK_MEMORY (&secret,sizeof(secret));
					unmap_file( output_map );
					unmap_file( input_map  );
					close_os_file( output_map.os_file );
					close_os_file( input_map.os_file  );
					remove( output_filename );
					errx( "Error: Catena_Strong_f failed with error code %d...\n"
					      "Allocating too much memory?\n", static_cast<int>(r) );
				}
				zero_sensitive( &(secret.catena.strong), sizeof(secret.catena.strong) );
			}
			zero_sensitive( secret.first_password, sizeof(secret.first_password) );
			// Hash the output into encryption and authentication keys.
			static_assert (sizeof(secret.hash_output) == (Block_Bytes * 2));
			Skein_f::hash( &(secret.ubi_data),
				       secret.hash_output,
				       secret.hash_output,
				       Block_Bytes,
				       (Block_Bytes * 2) );
			memcpy( secret.enc_key,
				secret.hash_output,
				Block_Bytes );
			memcpy( secret.auth_key,
				secret.hash_output + Block_Bytes,
				Block_Bytes );
			zero_sensitive( secret.hash_output, sizeof(secret.hash_output) );
			Threefish_f::rekey( &(secret.ctr_data.threefish_data),
					    secret.enc_key,
					    pub.tf_tweak );
		}
		// Setup the public portion of the header
		u8_t *out = output_map.ptr;

		memcpy( out, Dragonfly_V1_ID, sizeof(Dragonfly_V1_ID) );
		out += sizeof(Dragonfly_V1_ID);
		(*reinterpret_cast<u64_t*>(out)) = output_map.size;
		out += sizeof(u64_t);
		(*out++) = catena_input.g_low;
		(*out++) = catena_input.g_high;
		(*out++) = catena_input.lambda;
		(*out++) = catena_input.use_phi;
		memcpy( out, pub.tf_tweak, Tweak_Bytes );
		out += Tweak_Bytes;
		memcpy( out, pub.catena_salt, Salt_Bytes );
		out += Salt_Bytes;
		memcpy( out, pub.ctr_nonce, CTR_f::Nonce_Bytes );
		out += CTR_f::Nonce_Bytes;
		// Setup the to-be-encrypted portion of the header.
		{
			_CTIME_CONST (int) Zeroes = sizeof(u64_t) * 2;
			{
				u8_t zeroes [Zeroes] = { 0 };
				CTR_f::set_nonce( &(secret.ctr_data),
						  pub.ctr_nonce );
				// The encrypted, reserved portion of the header.
				CTR_f::xorcrypt( &(secret.ctr_data),
						 out,
						 zeroes,
						 Zeroes );
			}
			out += Zeroes;
			CTR_f::xorcrypt( &(secret.ctr_data),
					 out,
					 input_map.ptr,
					 inpupt_map.size,
					 Zeroes );
			out += input_map.size;
		}
		{
			Skein_f::mac( &(secret.ubi_data),
				      out,
				      output_map.ptr,
				      secret.auth_key,
				      MAC_Bytes,
				      output_map.size - MAC_Bytes );
		}
		zero_sensitive( &secret, sizeof(secret) );

		UNLOCK_MEMORY (&secret,sizeof(secret));

		sync_map( output_map );
		unmap_file( output_map );
		unmap_file( input_map );
		close_os_file( output_map.os_file );
		close_os_file( input_map.os_file );
	}/* ~ void encrypt (...) */
	void decrypt (OS_Map &input_map,
		      OS_Map &output_map,
		      char const *output_filename)
	{
		output_map.size = input_map.size - Visible_Metadata_Bytes;

		_CTIME_CONST (int) Minimum_Possible_File_Size = Visible_Metadata_Bytes + 1;
		if( input_map.size < Minimum_Possible_File_Size ) {
			close_os_file( output_map.os_file );
			remove( output_filename );
			unmap_file( input_map );
			close_os_file( input_map.os_file );
			errx( "Error: Input file doesn't appear to be large enough to be a SSC_DRAGONFLY_V1 encrypted file\n" );
		}
		set_os_file_size( output_map.os_file, output_map.size );
		map_file( output_map, false );
		u8_t const *in = input_map.ptr;
		struct {
			u64_t               tweak       [Threefish_f::External_Key_Words];
			alignas(u64_t) u8_t catena_salt [Salt_Bytes];
			alignas(u64_t) u8_t ctr_nonce   [CTR_f::Nonce_Bytes];
			u64_t               header_size;
			u8_t                header_id   [sizeof(Dragonfly_V1_ID)];
			u8_t                g_low;
			u8_t                g_high;
			u8_t                lambda;
			u8_t                use_phi;
		} pub;
		// Copy all the fields of the Dragonfly_V1 header from the memory-mapped input file into the pub struct.
		{
			memcpy( pub.header_id, in, sizeof(pub.header_id) );
			in += sizeof(pub.header_id);
			pub.header_size = (*reinterpret_cast<u64_t*>(in));
			in += sizeof(u64_t);
			pub.g_low   = (*in++);
			pub.g_high  = (*in++);
			pub.lambda  = (*in++);
			pub.use_phi = (*in++);
			memcpy( pub.tweak, in, Tweak_Bytes );
			in += Tweak_Bytes;
			memcpy( pub.catena_salt, in, Salt_Bytes );
			in += Salt_Bytes;
			memcpy( pub.ctr_nonce, in, CTR_f::Nonce_Bytes );
			in += CTR_f::Nonce_Bytes;
		}
		if( memcmp( pub.header_id, Dragonfly_V1_ID, sizeof(Dragonfly_V1_ID) ) != 0 ) {
			unmap_file( input_map );
			unmap_file( output_map );
			close_os_file( input_map.os_file );
			close_os_file( output_map.os_file );
			remove( output_filename );
			errx( "Error: Not a Dragonfly_V1 encrypted file." );
		}
		struct {
			CTR_Data_t           ctr_data;
			typename UBI_f::Data ubi_data;
			union {
				typename Catena_Strong_f::Data strong;
				typename Catena_Safe_f::Data   safe;
			} catena;
			u64_t                enc_key  [Threefish_f::External_Key_Words];
			alignas(u64_t) u8_t  auth_key [Block_Bytes];
			alignas(u64_t) u8_t  hash_buf [Block_Bytes * 2];
			u8_t                 password [Password_Buffer_Bytes];
			alignas(u64_t) u8_t  gen_mac  [MAC_Bytes];
		} secret;

		LOCK_MEMORY (&secret,sizeof(secret));

		int password_size = obtain_password<Password_Buffer_Bytes>( secret.password, Password_Prompt );
		if( !pub.use_phi ) {
			memcpy( secret.catena.safe.salt,
				pub.catena_salt,
				sizeof(pub.catena_salt) );
			auto r = Catena_Safe_f::call( &(secret.catena.safe),
					              secret.hash_buf,
						      secret.password,
						      password_size,
						      pub.g_low,
						      pub.g_high,
						      pub.lambda );
			if( r != Catena_Safe_f::Return_E::Success ) {
				zero_sensitive( &secret, sizeof(secret) );
				UNLOCK_MEMORY (&secret,sizeof(secret));
				unmap_file( output_map );
				unmap_file( input_map );
				close_os_file( output_map.os_file );
				close_os_file( input_map.os_file );
				remove( output_filename );
				errx( "Error: Catena_Safe_f failed with error code %d...\n"
				      "Do you have enough memory to decrypt this file?\n", static_cast<int>(r) );
			}
			zero_sensitive( &(secret.catena.safe), sizeof(secret.catena.safe) );
		} else {
			memcpy( secret.catena.strong.salt,
				pub.catena_salt,
				sizeof(pub.catena_salt) );
			auto r = Catena_Strong_f::call( &(secret.catena.strong),
					                secret.hash_buf,
							secret.password,
							password_size,
							pub.g_low,
							pub.g_high,
							pub.lambda );
			if( r != Catena_Strong_f::Return_E::Success ) {
				zero_sensitive( &secret, sizeof(secret) );
				UNLOCK_MEMORY (&secret,sizeof(secret));
				unmap_file( output_map );
				unmap_file( input_map );
				close_os_file( output_map.os_file );
				close_os_file( input_map.os_file );
				remove( output_filename );
				errx( "Error: Catena_Strong_f failed with error code %d...\n"
				      "Do you have enough memory to decrypt this file?\n", static_cast<int>(r) );
			}
			zero_sensitive( &(secret.catena.strong), sizeof(secret.catena.strong) );
		}
		{// Generate the keys.
			Skein_f::hash( &(secret.ubi_data),
				       secret.hash_buf,
				       secret.hash_buf,
				       Block_Bytes,
				       (Block_Bytes * 2) );
			memcpy( secret.enc_key,
				secret.hash_buf,
				Block_Bytes );
			memcpy( secret.auth_key,
				secret.hash_buf + Block_Bytes,
				Block_Bytes );
			zero_sensitive( secret.hash_buf, sizeof(secret.hash_buf) );
			{
				Skein_f::mac( &secret.ubi_data,
					      secret.gen_mac,
					      input_map.ptr,
					      secret.auth_key,
					      sizeof(secret.gen_mac),
					      input_map.size - MAC_Bytes );
				if( constant_time_memcmp( secret.gen_mac, (input_map.ptr + input_map.size - MAC_Bytes), MAC_Bytes ) != 0 ) {
					zero_sensitive( &crypto, sizeof(crypto) );
					UNLOCK_MEMORY (&crypto,sizeof(crypto));
					unmap_file( input_map  );
					unmap_file( output_map );
					close_os_file( input_map.os_file );
					close_os_file( output_map.os_file );
					remove( output_filename );
					errx( "Error: Authentication failed.\n"
					      "Possibilities: Wrong password, the file is corrupted, or it has been tampered with.\n" );
				}
			}
			Threefish_f::rekey( &(secret.ctr_data.threefish_data),
					    secret.enc_key,
					    pub.tweak );
		}
		u64_t plaintext_size = output_map.size;
		{
			u64_t padding_bytes;
			CTR_f::xorcrypt( &secret.ctr_data,
					 &padding_bytes,
					 in,
					 sizeof(u64_t) );
			plaintext_size -= padding_bytes;
			in += (padding_bytes + (sizeof(u64_t) * 2)); // Skip the second word. It is reserved.
			CTR_f::xorcrypt( &secret.ctr_data,
					 output_map.ptr,
					 in,
					 plaintext_size,
					 (sizeof(u64_t) * 2) );
		}
		zero_sensitive( &secret, sizeof(secret) );
		UNLOCK_MEMORY (&secret,sizeof(secret));
		sync_map( output_map );
		unmap_file( output_map );
		unmap_file( input_map  );
		if( plaintext_size != output_map.size )
			set_os_file_size( output_map.os_file, plaintext_size );
		close_os_file( output_map.os_file );
		close_os_file( input_map.os_file  );
	}/* ~ void decrypt (...) */
	void dump_header (OS_Map &input_map,
			  char const *input_filename)
	{
		_CTIME_CONST (int) Minimum_Size = Visible_Metadata_Bytes + 1;
		if( input_map.size < Minimum_Size ) {
			unmap_file( input_map );
			close_os_file( input_map.os_file );
			errx( "File `%s` looks too small to be SSC_Dragonfly_V1 encrypted\n", input_filename );
		}
		struct {
			u8_t id     [sizeof(Dragonfly_V1_ID)];
			u64_t total_size;
			u8_t  g_low;
			u8_t  g_high;
			u8_t  lambda;
			u8_t  use_phi;
			u8_t  tweak [Tweak_Bytes];
			u8_t  salt  [Salt_Bytes];
			u8_t  nonce [CTR_f::Nonce_Bytes];
		} header;
		u8_t mac [MAC_Bytes];
		{
			u8_t const *p = input_map.ptr;
			memcpy( header.id, sizeof(header.id) );
			p += sizeof(header.id);
			header.total_size = (*reinterpret_cast<u64_t*>(p));
			p += sizeof(header.total_size);
			header.g_low   = (*p++);
			header.g_high  = (*p++);
			header.lambda  = (*p++);
			header.use_phi = (*p++);
			memcpy( header.tweak, p, sizeof(header.tweak) );
			p += sizeof(header.tweak);
			memcpy( header.salt, p, sizeof(header.salt) );
			p += sizeof(header.salt);
			memcpy( header.nonce, p, sizeof(header.nonce) );
			p += sizeof(header.nonce);
			p = os_map.ptr + os_map.size - MAC_Bytes;
			memcpy( mac, p, sizeof(mac) );
		}
		unmap_file( input_map );
		close_os_file( input_map.os_file );

		header.id[ sizeof(header.id) - 1 ] = '\0';
		fprintf( stdout, "File Header ID : %s\n", reinterpret_cast<char*>(header.id) );
		fprintf( stdout, "File Size      : %zu\n", header.total_size );
		fprintf( stdout, "Garlic Low: %c\n", header.g_low );
		fprintf( stdout, "Garlic High: %c\n", header.g_high );
		fprintf( stdout, "Lambda: %c\n", header.lambda );
		if( !header.use_phi )
			fprintf( stdout, "The Phi function is not used.\n" );
		else
			fprintf( stdout, "The Phi function is used!\n" );
		fputs(           "Threefish Tweak : ", stdout );
		print_integral_buffer<u8_t>( header.tweak, sizeof(header.tweak) );
		fputs(           "Catena Salt : ", stdout );
		print_integral_buffer<u8_t>( header.salt, sizeof(header.salt) );
		fputs(           "CTR Salt : ", stdout );
		print_integral_buffer<u8_t>( header.nonce, sizeof(header.nonce) );
	}
}/* ~ namespace ssc::crypto_impl::dragonfly_v1 */
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
