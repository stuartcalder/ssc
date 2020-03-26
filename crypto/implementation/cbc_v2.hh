/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

#ifndef __SSC_CBC_V2__
#	define __SSC_CBC_V2__
#else
#	error '__SSC_CBC_V2__ Already defined'
#endif

#include "common.hh"

#include <cstring>
#include <cstdlib>
#include <string>
#include <climits>

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/cipher_block_chaining.hh>

namespace ssc::crypto_impl::cbc_v2 {
	_CTIME_CONST(auto&)	CBC_V2_ID = "3CRYPT_CBC_V2";
	using CBC_t = Cipher_Block_Chaining<Threefish_t, Block_Bits>;

	struct _PUBLIC CBC_V2_Header {
		char			id		[sizeof(CBC_V2_ID)];
		u64_t			total_size;
		u8_t			tweak		[Tweak_Bytes];
		u8_t			sspkdf_salt	[Salt_Bytes];
		u8_t			cbc_iv		[Block_Bytes];
		u32_t			num_iter;
		u32_t			num_concat;
		_CTIME_CONST(int)	Total_Size = sizeof(id) + sizeof(total_size) + sizeof(tweak) +
			                             sizeof(sspkdf_salt) + sizeof(cbc_iv) + sizeof(num_iter) + sizeof(num_concat);
	};

	void _PUBLIC
	encrypt (Input const & input_abstr);

	void _PUBLIC
	decrypt (char const *__restrict input_filename,
	 	 char const *__restrict output_filename);

	void _PUBLIC
	dump_header (char const *filename);

}/*namespace ssc::crypto_impl::cbc_v2*/
