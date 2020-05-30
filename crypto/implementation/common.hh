/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

/* SSC General Headers */
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
/* SSC Crypto Headers */
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish_f.hh>
#include <ssc/crypto/unique_block_iteration_f.hh>
#include <ssc/crypto/cipher_block_chaining_f.hh>
#include <ssc/crypto/skein_f.hh>
#include <ssc/crypto/skein_csprng_f.hh>
/* SSC File Headers */
#include <ssc/files/os_map.hh>
/* SSC Memory I/O Headers */
#include <ssc/memory/os_memory_locking.hh>
/* SSC Interface Headers */
#include <ssc/interface/terminal_ui_f.hh>
/* C Library Headers */
#include <climits>
#include <cstring>
/* C++ Library Headers */
#include <string>

#ifndef NEW_LINE
#	if    defined (SSC_OS_UNIXLIKE)
#		define NEW_LINE "\n"
#	elif  defined (SSC_OS_WINDOWS)
#		define NEW_LINE "\n\r"
#	else
#		error 'Unsupported OS'
#	endif
#else
#	error 'NEW_LINE Already Defined'
#endif

#ifndef OS_PROMPT
#	define OS_PROMPT NEW_LINE "> "
#else
#	error 'OS_PROMPT Already Defined'
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
		Tweak_Words = Tweak_Bytes / sizeof(u64_t),
		Max_Password_Chars = 120,
		Max_Entropy_Chars = 120,
		Password_Buffer_Bytes = Max_Password_Chars + 1,
		Supplement_Entropy_Buffer_Bytes = Max_Entropy_Chars + 1
	};
	static constexpr auto &Password_Prompt = "Please input a password (max length 120 characters)." OS_PROMPT ;
	static constexpr auto &Password_Reentry_Prompt = "Please input the same password again (max length 120 characters)." OS_PROMPT ;
	static constexpr auto &Entropy_Prompt = "Please input up to 120 random characters." OS_PROMPT ;
	using Threefish_f   = Threefish_F<Block_Bits>;              // Precomputed-keyschedule Threefish.
	using UBI_f         = Unique_Block_Iteration_F<Block_Bits>; // UBI for Skein hashing.
	using Skein_f       = Skein_F<Block_Bits>;                  // Interface to UBI.
	using CSPRNG_f      = Skein_CSPRNG_F<Block_Bits>;           // UBI-based PRNG.
	using Terminal_UI_f = Terminal_UI_F<u8_t,Password_Buffer_Bytes>; // Using u8_t for password bytes, with Password_Buffer_Bytes as the max buffer size.

	struct SSC_PUBLIC
	SSPKDF_Input
	{
		bool	    supplement_os_entropy; // Whether to supplement entropy in consuming procedure.
		u32_t	    number_iterations; // Number of times to iterate SSPKDF.
		u32_t	    number_concatenations; // Number of times to concatenate password together in SSPKDF.
	};
	struct SSC_PUBLIC
	Catena_Input
	{
		u64_t padding_bytes;
		bool supplement_os_entropy;
		u8_t g_low;
		u8_t g_high;
		u8_t lambda;
		u8_t use_phi;
	};

	inline void
	supplement_entropy (SSC_RESTRICT (typename CSPRNG_f::Data*) data,
			    SSC_RESTRICT (u8_t*)                    hash,
			    SSC_RESTRICT (u8_t*)                    input)
	{
		int num_input_chars = Terminal_UI_f::obtain_password( input, Entropy_Prompt );
		Skein_f::hash_native( &(data->skein_data),
				      hash,
				      input,
				      num_input_chars );
		CSPRNG_f::reseed( data, hash );
	}
}/* ~ namespace ssc::crypto_impl */
#undef OS_PROMPT
#undef NEW_LINE
