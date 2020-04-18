/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
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
#include <ssc/interface/terminal.hh>
/* C Library Headers */
#include <climits>
#include <cstring>
/* C++ Library Headers */
#include <string>

#ifndef NEW_LINE
#	if    defined (__UnixLike__)
#		define NEW_LINE "\n"
#	elif  defined (__Windows__)
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

namespace ssc::crypto_impl
{
	static_assert (CHAR_BIT == 8);
	_CTIME_CONST (int)	Block_Bits  = 512;
	_CTIME_CONST (int)	Block_Bytes = Block_Bits / CHAR_BIT;
	_CTIME_CONST (int)	MAC_Bytes   = Block_Bytes;

	_CTIME_CONST (int)	Tweak_Bits  = 128;
	_CTIME_CONST (int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;
	_CTIME_CONST (int)      Tweak_Words = Tweak_Bytes / sizeof(u64_t);

	_CTIME_CONST (int)	Max_Password_Chars = 120;
	_CTIME_CONST (int)	Max_Entropy_Chars  = 120;
	_CTIME_CONST (int)	Password_Buffer_Bytes   = Max_Password_Chars + 1;
	_CTIME_CONST (int)      Supplement_Entropy_Buffer_Bytes = Max_Entropy_Chars + Block_Bytes + 1;
	_CTIME_CONST (auto&)	Password_Prompt	        = "Please input a password (max length 120 characters)." OS_PROMPT ;
	_CTIME_CONST (auto&)	Password_Reentry_Prompt = "Please input the same password again (max length 120 characters)." OS_PROMPT ;
	_CTIME_CONST (auto&)	Entropy_Prompt		= "Please input up to 120 random characters." OS_PROMPT ;
	using Threefish_f = Threefish_F<Block_Bits>; // Precomputed-keyschedule Threefish.
	using UBI_f       = Unique_Block_Iteration_F<Block_Bits>; // UBI for Skein hashing.
	using Skein_f     = Skein_F<Block_Bits>; // Interface to UBI.
	using CSPRNG_f    = Skein_CSPRNG_F<Block_Bits>; // UBI-based PRNG.

	struct _PUBLIC SSPKDF_Input {
		bool	    supplement_os_entropy; // Whether to supplement entropy in consuming procedure.
		u32_t	    number_iterations; // Number of times to iterate SSPKDF.
		u32_t	    number_concatenations; // Number of times to concatenate password together in SSPKDF.
	};
	struct _PUBLIC Catena_Input {
		bool supplement_os_entropy;
		u8_t g_low;
		u8_t g_high;
		u8_t lambda;
		u8_t use_phi;
	};

	inline void supplement_entropy (_RESTRICT (typename CSPRNG_f::Data *) data,
			                _RESTRICT (u8_t *)                    hash,
					_RESTRICT (u8_t *)                    input)
	{
		_CTIME_CONST (int) Input_Size = Max_Entropy_Chars + 1;
		int num_input_chars = obtain_password<Input_Size>( input, Entropy_Prompt );
		Skein_f::hash_native( &(data->skein_data), hash, input, num_input_chars );
		CSPRNG_f::reseed( data, hash );
	}
}/* ~ namespace ssc::crypto_impl */
#undef OS_PROMPT
#undef NEW_LINE
