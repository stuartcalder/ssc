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
#define __SSC_CBC_V2__ 1
#endif

#include <cstring>
#include <cstdlib>
#include <string>

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/cipher_block_chaining.hh>
#include <ssc/crypto/sspkdf.hh>

namespace ssc::cbc_v2 {
	static_assert (CHAR_BIT == 8);
	// Compile-Time Constants
	static constexpr auto const & CBC_V2_ID = "3CRYPT_CBC_V2";
	static constexpr auto const Salt_Bits = 128;
	static constexpr auto const Salt_Bytes = Salt_Bits / CHAR_BIT;
	static constexpr auto const Tweak_Bits = 128;
	static constexpr auto const Tweak_Bytes = Tweak_Bits / CHAR_BIT;
	static constexpr auto const Block_Bits = 512;
	static constexpr auto const Block_Bytes = Block_Bits / CHAR_BIT;
	static constexpr auto const MAC_Bytes = Block_Bytes;
	static constexpr auto const Max_Password_Length = 120;
	// Compile-Time Type Aliases
	using Threefish_t = Threefish<Block_Bits>;
	using Skein_t     = Skein    <Block_Bits>;
	using CBC_t	  = Cipher_Block_Chaining<Threefish_t, Block_Bits>;

	struct DLL_PUBLIC Encrypt_Input {
		std::string input_filename;
		std::string output_filename;
		u32_t       number_iterations;
		u32_t       number_concatenations;
	};/*struct Encrypt_Input */

	template <size_t ID_Bytes>
	struct DLL_PUBLIC Sspkdf_Header {
		char  id          [ID_Bytes];
		u64_t total_size;
		u8_t  tweak	  [Tweak_Bytes];
		u8_t  sspkdf_salt [Salt_Bytes];
		u8_t  cbc_iv      [Block_Bytes];
		u32_t num_iter;
		u32_t num_concat;
		static constexpr auto const Total_Size = sizeof(id) + sizeof(total_size) + sizeof(tweak) +
			                                 sizeof(sspkdf_salt) + sizeof(cbc_iv) + sizeof(num_iter) + sizeof(num_concat);
	};
	using CBC_V2_Header_t = Sspkdf_Header<sizeof(CBC_V2_ID)>;

	void DLL_PUBLIC
	encrypt (Encrypt_Input const & input_abstr);

	void DLL_PUBLIC
	decrypt (char const *__restrict input_filename,
	 	 char const *__restrict output_filename);

	void DLL_PUBLIC
	dump_header (char const *filename);
}/*namespace ssc::cbc_v2*/
