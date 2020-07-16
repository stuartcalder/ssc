/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

/* SSC General Headers */
#include <shim/macros.h>
#include <shim/operations.h>
#include <shim/map.h>
#include <shim/mlock.h>
/* SSC Crypto Headers */
#include <ssc/crypto/threefish_f.hh>
#include <ssc/crypto/unique_block_iteration_f.hh>
#include <ssc/crypto/cipher_block_chaining_f.hh>
#include <ssc/crypto/skein_f.hh>
#include <ssc/crypto/skein_csprng_f.hh>
/* SSC Interface Headers */
#include <ssc/interface/terminal_ui_f.hh>
/* C Library Headers */
#include <climits>
#include <cstring>
/* C++ Library Headers */
#include <string>

#ifndef NEW_LINE_
#	if    defined (SHIM_OS_UNIXLIKE)
#		define NEW_LINE_ "\n"
#	elif  defined (SHIM_OS_WINDOWS)
#		define NEW_LINE_ "\n\r"
#	else
#		error 'Unsupported OS'
#	endif
#else
#	error 'NEW_LINE_ Already Defined'
#endif

#ifndef OS_PROMPT_
#	define OS_PROMPT_ NEW_LINE_ "> "
#else
#	error 'OS_PROMPT_ Already Defined'
#endif

namespace ssc::crypto_impl {
	static_assert (CHAR_BIT == 8,
		       "We require 8-bit bytes.");
	enum Int_Constants: int {
		Block_Bits = 512,
		Block_Bytes = Block_Bits / CHAR_BIT,
		MAC_Bytes = Block_Bytes,
		Tweak_Bits = 128,
		Tweak_Bytes = Tweak_Bits / CHAR_BIT,
		Tweak_Words = Tweak_Bytes / sizeof(uint64_t),
		Max_Password_Chars = 120,
		Max_Entropy_Chars = 120,
		Password_Buffer_Bytes = Max_Password_Chars + 1,
		Supplement_Entropy_Buffer_Bytes = Max_Entropy_Chars + 1
	};
	static constexpr auto &Password_Prompt = "Please input a password (max length 120 characters)." OS_PROMPT_ ;
	static constexpr auto &Password_Reentry_Prompt = "Please input the same password again (max length 120 characters)." OS_PROMPT_ ;
	static constexpr auto &Entropy_Prompt = "Please input up to 120 random characters." OS_PROMPT_ ;
	using Threefish_f   = Threefish_F<Block_Bits>;              // Precomputed-keyschedule Threefish.
	using UBI_f         = Unique_Block_Iteration_F<Block_Bits>; // UBI for Skein hashing.
	using Skein_f       = Skein_F<Block_Bits>;                  // Interface to UBI.
	using CSPRNG_f      = Skein_CSPRNG_F<Block_Bits>;           // UBI-based PRNG.
	using Terminal_UI_f = Terminal_UI_F<uint8_t,Password_Buffer_Bytes>; // Using uint8_t for password bytes, with Password_Buffer_Bytes as the max buffer size.

	struct SHIM_PUBLIC
	SSPKDF_Input
	{
		bool	 supplement_os_entropy; // Whether to supplement entropy in consuming procedure.
		uint32_t number_iterations; // Number of times to iterate SSPKDF.
		uint32_t number_concatenations; // Number of times to concatenate password together in SSPKDF.
	};
	struct SHIM_PUBLIC
	Catena_Input
	{
		uint64_t padding_bytes;
		bool     supplement_os_entropy;
		uint8_t  g_low;
		uint8_t  g_high;
		uint8_t  lambda;
		uint8_t  use_phi;
	};

	inline void
	supplement_entropy (typename CSPRNG_f::Data * SHIM_RESTRICT data,
			    uint8_t *                 SHIM_RESTRICT hash,
			    uint8_t *                 SHIM_RESTRICT input)
	{
		int num_input_chars = Terminal_UI_f::obtain_password( input, Entropy_Prompt );
		Skein_f::hash_native( &data->skein_data,
				      hash,
				      input,
				      num_input_chars );
		CSPRNG_f::reseed( data, hash );
	}
}/* ~ namespace ssc::crypto_impl */
#undef OS_PROMPT_
#undef NEW_LINE_
