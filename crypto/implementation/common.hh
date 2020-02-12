#pragma once

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/skein_csprng.hh>
#include <ssc/memory/os_memory_locking.hh>
#include <ssc/interface/terminal.hh>

#include <climits>
#include <cstring>
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
	_CTIME_CONST(auto)	Password_Prompt	        = "Please input a password (max length 120 characters)." OS_PROMPT;
	_CTIME_CONST(auto)	Password_Reentry_Prompt = "Please input the same password again (max length 120 characters)." OS_PROMPT;
	_CTIME_CONST(auto)	Entropy_Prompt		= "Please input up to 120 random characters." OS_PROMPT;

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

#if 0
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
#endif
	template <int Buffer_Size>
	int obtain_password (char       *password_buffer,
			     char const *entry_prompt,
			     int const  min_pw_size = 1,
			     int const  max_pw_size = Buffer_Size - 1)
	{
		int size;
		while (true) {
			Terminal term;
			size = term.get_sensitive_string<Buffer_Size>( password_buffer, entry_prompt );
			if (size < min_pw_size) {
				term.notify( "Password is not long enough." NEW_LINE );
			} else if (size > max_pw_size) {
				term.notify( "Password is too long." NEW_LINE );
			} else {
				break;
			}
		}
		return size;
	} /* obtain_password(password_buffer,entry_prompt) */

	template <int Buffer_Size>
	int obtain_password (char *password_buffer,
			     char *check_buffer,
			     char const *entry_prompt,
			     char const *reentry_prompt,
			     int const  min_pw_size = 1,
			     int const  max_pw_size = Buffer_Size - 1)
	{
		using namespace std;
		int size;
		while (true) {
			Terminal term;
			size = term.get_sensitive_string<Buffer_Size>( password_buffer, entry_prompt );
			static_cast<void>(term.get_sensitive_string<Buffer_Size>( check_buffer, reentry_prompt ));
			if (memcmp( password_buffer, check_buffer, Buffer_Size ) == 0)
				break;
			term.notify( "Passwords do not match." );
		}
		return size;
	} /* obtain_password(password_buffer,check_buffer,entry_prompt,reentry_prompt) */

	_CTIME_CONST(int) Supplement_Entropy_Buffer_Bytes = Block_Bytes + Max_Entropy_Chars + 1;

#if 0
	void DLL_PUBLIC
	supplement_entropy (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer);
#endif
	inline void supplement_entropy (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer)
	{
		using namespace std;
		_CTIME_CONST(int) Hash_Size = Block_Bytes;
		_CTIME_CONST(int) Input_Size = Max_Entropy_Chars + 1;
		_CTIME_CONST(int) Buffer_Size = Hash_Size + Input_Size;

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
