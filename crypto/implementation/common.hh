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
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/skein_csprng.hh>
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

namespace ssc::crypto_impl {
	static_assert (CHAR_BIT == 8);
	_CTIME_CONST(int)	Block_Bits  = 512;
	_CTIME_CONST(int)	Block_Bytes = Block_Bits / CHAR_BIT;
	_CTIME_CONST(int)	MAC_Bytes   = Block_Bytes;

	_CTIME_CONST(int)	Salt_Bits   = 128;
	_CTIME_CONST(int)	Salt_Bytes  = Salt_Bits / CHAR_BIT;
	_CTIME_CONST(int)	Tweak_Bits  = 128;
	_CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;

	_CTIME_CONST(int)	Max_Password_Chars = 120;
	_CTIME_CONST(int)	Max_Entropy_Chars  = 120;
	_CTIME_CONST(int)	Password_Buffer_Bytes   = Max_Password_Chars + 1;
	_CTIME_CONST(auto&)	Password_Prompt	        = "Please input a password (max length 120 characters)." OS_PROMPT;
	_CTIME_CONST(auto&)	Password_Reentry_Prompt = "Please input the same password again (max length 120 characters)." OS_PROMPT;
	_CTIME_CONST(auto&)	Entropy_Prompt		= "Please input up to 120 random characters." OS_PROMPT;

	using Threefish_t = Threefish<Block_Bits>;
	using UBI_t       = Unique_Block_Iteration<Threefish_t, Block_Bits>;
	using Skein_t     = Skein<Block_Bits>;
	using CSPRNG_t    = Skein_CSPRNG<Block_Bits>;
	struct _PUBLIC Input {
		std::string	input_filename;
		std::string	output_filename;
		u32_t		number_sspkdf_iterations;
		u32_t		number_sspkdf_concatenations;
		bool		supplement_os_entropy;
	};

	_CTIME_CONST(int) Supplement_Entropy_Buffer_Bytes = Block_Bytes + Max_Entropy_Chars + 1;

	inline void supplement_entropy (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer)
	{
		using namespace std;
		_CTIME_CONST(int) Hash_Size = Block_Bytes;
		_CTIME_CONST(int) Input_Size = Max_Entropy_Chars + 1;

		static_assert (sizeof(u8_t) == sizeof(char));
		u8_t *hash  = buffer;
		char *input = reinterpret_cast<char*>(buffer + Hash_Size);
		int num_input_chars = obtain_password<Input_Size>( input, Entropy_Prompt );
		static_assert (Skein_t::State_Bytes == Hash_Size);
		skein.hash_native( hash, reinterpret_cast<u8_t*>(input), num_input_chars );
		static_assert (CSPRNG_t::State_Bytes == Hash_Size);
		csprng.reseed( hash );
	} /* supplement_entropy(csprng,skein,buffer) */

}/*namespace ssc::crypto_impl*/
#undef OS_PROMPT
#undef NEW_LINE
