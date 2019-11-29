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

#ifdef __SSC_CBC_V2__
#	error "Somehow, __SSC_CBC_V2__ is already defined..."
#endif

#define __SSC_CBC_V2__

#include "common.hh"

#include <cstring>
#include <cstdlib>
#include <string>
#include <climits>

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/skein_csprng.hh>
#include <ssc/crypto/cipher_block_chaining.hh>
#include <ssc/crypto/sspkdf.hh>

namespace ssc::cbc_v2 {
	static_assert (CHAR_BIT == 8);
	/* Compile-Time Constants */
	// CBC_V2_ID will be the "magic" C-string at the beginning of CBC_V2 encrypted files, to indicate the method to use for decryption.
	static constexpr auto const & CBC_V2_ID = "3CRYPT_CBC_V2";
	// For CBC_V2, we use the `sspkdf` key derivation function, which takes 128 bits (16 bytes) of random salt.
	static constexpr auto const Salt_Bits = 128;
	static constexpr auto const Salt_Bytes = Salt_Bits / CHAR_BIT;
	// All three variants of the Threefish tweakable block cipher use a 128-bit tweak.
	static constexpr auto const Tweak_Bits = 128;
	static constexpr auto const Tweak_Bytes = Tweak_Bits / CHAR_BIT;
	// CBC_V2 aims for 512 bits of security, so we'll be using 512-bit wide blocks and keys.
	static constexpr auto const Block_Bits = 512;
	static constexpr auto const Block_Bytes = Block_Bits / CHAR_BIT;
	// The Message Authentication Code appended to the end of CBC_V2 encrypted files shall have an authentication code the same width as an encrypted block.
	static constexpr auto const MAC_Bytes = Block_Bytes;
	// We will arbitrarily limit password lengths to 120 characters.
	static constexpr auto const Max_Password_Length = 120;
	// We will arbitrarily limit supplementary entropy characters to 120 characters.
	static constexpr auto const Max_Supplementary_Entropy_Chars = 120;
	/* OS-Specific Compile-Time Constants */
#if    defined (__UnixLike__)
	static_assert (Max_Password_Length == 120);
	static constexpr auto const Password_Prompt = "Please input a password (max length 120 characters).\n> ";
	static constexpr auto const Password_Reentry_Prompt = "Good. Please input the same password again (max length 120 characters).\n> ";
	static_assert (Max_Supplementary_Entropy_Chars == 120);
	static constexpr auto const Supplementary_Entropy_Prompt = "Please input up to 120 random characters.\n> ";
/* For the functions we're going to use in the win64 implementation of ssc::Terminal, we require
 * lines to be terminated by \n\r instead of just \n.
 */
#elif  defined (__Win64__)
	static_assert (Max_Password_Length == 120);
	static constexpr auto const Password_Prompt = "Please input a password (max length 120 characters).\n\r> ";
	static constexpr auto const Password_Reentry_Prompt = "Good. Please input the same password again (max length 120 characters).\n\r> ";
	static_assert (Max_Supplementary_Entropy_Chars == 120);
	static constexpr auto const Supplementary_Entropy_Prompt = "Please input up to 120 random characters.\n\r> ";
#else
#	error "Only defined for Unix-like operating system and 64-bit MS windows"
#endif
	/* Compile-Time Type Aliases */
	// We shall use Threefish with the desired block width.
	using Threefish_t = Threefish<Block_Bits>;
	// We shall use Skein with the desired block width.
	using Skein_t     = Skein    <Block_Bits, true>;
	// We shall use Threefish in cipher-block-chaining mode, with the specified block width.
	using CBC_t	  = Cipher_Block_Chaining<Threefish_t, Block_Bits>;
	// We shall use the Skein_CSPRNG as a cryptographically secure PRNG, with the specified block width.
	using CSPRNG_t	  = Skein_CSPRNG<Block_Bits>;

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
	encrypt (Input const & input_abstr);

	void DLL_PUBLIC
	decrypt (char const *__restrict input_filename,
	 	 char const *__restrict output_filename);

	void DLL_PUBLIC
	dump_header (char const *filename);

}/*namespace ssc::cbc_v2*/
