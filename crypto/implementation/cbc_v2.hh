/*
Copyright 2019 (c) Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
	_CTIME_CONST(auto &)	CBC_V2_ID = "3CRYPT_CBC_V2";
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
