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
}/* ~ namespace ssc::crypto_impl::dragonfly_v1 */
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
