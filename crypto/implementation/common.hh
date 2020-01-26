#pragma once

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/skein_csprng.hh>
#include <ssc/memory/os_memory_locking.hh>

#include <climits>
#include <cstring>
#include <string>

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error 'Already defined'
#endif

#ifndef OS_PROMPT
#	if    defined (__UnixLike__)
#		define OS_PROMPT	"\n> "
#	elif  defined (__Windows__)
#		define OS_PROMPT	"\n\r> "
#	else
#		error 'Unsupported OS'
#	endif
#else
#	error 'Already defined'
#endif

namespace ssc::crypto_impl {
	static_assert (CHAR_BIT == 8);
	CTIME_CONST(int)	Block_Bits  = 512;
	CTIME_CONST(int)	Block_Bytes = Block_Bits / CHAR_BIT;
	CTIME_CONST(int)	MAC_Bytes   = Block_Bytes;

	CTIME_CONST(int)	Salt_Bits   = 128;
	CTIME_CONST(int)	Salt_Bytes  = Salt_Bits / CHAR_BIT;
	CTIME_CONST(int)	Tweak_Bits  = 128;
	CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;

	CTIME_CONST(int)	Max_Password_Chars = 120;
	CTIME_CONST(int)	Max_Entropy_Chars  = 120;
	CTIME_CONST(int)	Password_Buffer_Bytes   = Max_Password_Chars + 1;
	CTIME_CONST(auto)	Password_Prompt	        = "Please input a password (max length 120 characters)." OS_PROMPT;
	CTIME_CONST(auto)	Password_Reentry_Prompt = "Please input the same password again (max length 120 characters)." OS_PROMPT;
	CTIME_CONST(auto)	Entropy_Prompt		= "Please input up to 120 random characters." OS_PROMPT;

	using Threefish_t =	Threefish<Block_Bits>;
	using UBI_t       =     Unique_Block_Iteration<Threefish_t, Block_Bits>;
	using Skein_t     =	Skein<Block_Bits>;
	using CSPRNG_t    =	Skein_CSPRNG<Block_Bits>;
	struct DLL_PUBLIC Input {
		std::string	input_filename;
		std::string	output_filename;
		u32_t		number_sspkdf_iterations;
		u32_t		number_sspkdf_concatenations;
		bool		supplement_os_entropy;
	};

	int DLL_PUBLIC
	obtain_password (char       *password_buffer,
			 char const *entry_prompt,
			 int const  buffer_size);

	int DLL_PUBLIC
	obtain_password (char       *password_buffer,
			 char       *check_buffer,
			 char const *entry_prompt,
			 char const *reentry_prompt,
			 int const  buffer_size);

	CTIME_CONST(int) Supplement_Entropy_Buffer_Bytes = Block_Bytes + Max_Entropy_Chars + 1;

	void DLL_PUBLIC
	supplement_entropy (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer);

}/*namespace ssc::crypto_impl*/
#undef OS_PROMPT
#undef CTIME_CONST
