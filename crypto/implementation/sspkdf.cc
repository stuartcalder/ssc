/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include <shim/macros.h>
#include <shim/operations.h>
#include <shim/mlock.h>

#include <cstdlib>
#include <climits>
#include <ssc/crypto/skein_f.hh>
#include <ssc/general/macros.hh>
#include <ssc/crypto/operations.hh>
#include "sspkdf.hh"

namespace ssc::crypto_impl {
	static_assert (CHAR_BIT == 8);

	void
	sspkdf (typename UBI_f::Data * SHIM_RESTRICT ubi_data,
		uint8_t *              SHIM_RESTRICT output,
		uint8_t const *        SHIM_RESTRICT password,
		int const                            password_size,
		uint8_t const *        SHIM_RESTRICT salt,
		uint32_t const                       num_iter,
		uint32_t const                       num_concat)

	{
		enum {
			State_Bits = 512,
			State_Bytes = State_Bits / CHAR_BIT,
			Salt_Bits = 128,
			Salt_Bytes = Salt_Bits / CHAR_BIT
		};

		uint64_t const concat_size = (static_cast<uint64_t>(password_size) + Salt_Bytes + sizeof(uint32_t)) * static_cast<uint64_t>(num_concat);
		uint8_t * const concat_buffer = static_cast<uint8_t*>(std::malloc( concat_size ));
		if( concat_buffer == nullptr )
			SHIM_ERRX ("Error: SSPKDF failed to malloc\n");
		{
			uint32_t index = 0;
			uint8_t *buf_ptr = concat_buffer;
			uint8_t * const buf_end = buf_ptr + concat_size;
			while( buf_ptr < buf_end ) {
				std::memcpy( buf_ptr, password, password_size);
				buf_ptr += password_size;
				std::memcpy( buf_ptr, salt, Salt_Bytes );
				buf_ptr += Salt_Bytes;
				std::memcpy( buf_ptr, &index, sizeof(index) );
				//*(reinterpret_cast<uint32_t*>(buf_ptr)) = index;
				buf_ptr += sizeof(index);
				++index;
			}
		}
		{
			alignas(uint64_t) uint8_t key    [Block_Bytes];
			alignas(uint64_t) uint8_t buffer [Block_Bytes];

			Skein_f::hash_native( ubi_data, key, concat_buffer, concat_size );
			Skein_f::mac( ubi_data, buffer, concat_buffer, key, sizeof(buffer), concat_size );
			shim_secure_zero( concat_buffer, concat_size );
			std::free( concat_buffer );
			SSC_XOR (key, buffer, State_Bytes);

			for (uint32_t i = 1; i < num_iter; ++i) {
				Skein_f::mac( ubi_data, buffer, buffer, key, sizeof(buffer), sizeof(buffer) );
				SSC_XOR (key, buffer, State_Bytes);
			}
			Skein_f::hash_native( ubi_data, output, buffer, sizeof(buffer) );
			shim_secure_zero( key   , sizeof(key)    );
			shim_secure_zero( buffer, sizeof(buffer) );
		}
	}
} /* ! namespace ssc::crypto_impl */
