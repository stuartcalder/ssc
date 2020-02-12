#include "common.hh"
#include <cstring>
#include <ssc/interface/terminal.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/memory/os_memory_locking.hh>
#include <ssc/general/symbols.hh>

namespace ssc::crypto_impl
{
#if 0
	int obtain_password (char       *password_buffer,
			     char const *entry_prompt,
			     int const  buffer_size)
	{
		std::memset( password_buffer, 0, buffer_size );

		Terminal term;
		return term.get_pw( password_buffer, buffer_size - 1, 1, entry_prompt );
	} /* obtain_password(password,prompt,buffer_size) */

	int obtain_password (char       *password_buffer,
			     char       *check_buffer,
			     char const *entry_prompt,
			     char const *reentry_prompt,
			     int const  buffer_size)
	{
		using namespace std;
		int pw_size;
		while (true) {
			Terminal term;
			memset( password_buffer, 0, buffer_size );
			memset( check_buffer   , 0, buffer_size );
			pw_size =         term.get_pw( password_buffer, buffer_size - 1, 1, entry_prompt   );
			static_cast<void>(term.get_pw( check_buffer   , buffer_size - 1, 1, reentry_prompt ));
			if (memcmp( password_buffer, check_buffer, buffer_size ) == 0)
				break;
			term.notify( "Passwords do not match." );
		}
		return pw_size;
	} /* obtain_password(password_buffer,check_buffer,entry_prompt,reentry_prompt,buffer_size) */
#endif

#if 0
	void supplement_entropy (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer)
	{
		using namespace std;
		_CTIME_CONST(int) Hash_Size   = Block_Bytes;
		_CTIME_CONST(int) Input_Size  = Max_Entropy_Chars + 1;
		_CTIME_CONST(int) Buffer_Size = Hash_Size + Input_Size;

		static_assert (sizeof(u8_t) == sizeof(char));
		u8_t	*hash  = buffer;
		char	*input = reinterpret_cast<char *>(buffer + Hash_Size);

		int num_input_chars = obtain_password( input, Entropy_Prompt, Input_Size  );

		static_assert (Skein_t::State_Bytes == Hash_Size);
		skein.hash_native( hash, reinterpret_cast<u8_t *>(input), num_input_chars );
		static_assert (Hash_Size == CSPRNG_t::State_Bytes);
		csprng.reseed( hash );
	} /* supplement_entropy(csprng,skein,buffer) */
#endif
}/*namespace ssc::crypto_impl*/
