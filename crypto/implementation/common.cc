#include "common.hh"
#include <cstring>
#include <ssc/interface/terminal.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/memory/os_memory_locking.hh>

namespace ssc::crypto_impl {
	int
	obtain_password (char       *password,
			 char const *entry_prompt,
			 int const   buffer_size)
	{
		std::memset( password, 0, buffer_size );

		Terminal term;
		return term.get_pw( password, buffer_size - 1, 1, entry_prompt );
	}

	int
	obtain_password (char       *password,
			 char const *entry_prompt,
			 char const *reentry_prompt,
			 int const   buffer_size)
	{
		using namespace std;
		int pw_size;
		char *check = new(std::nothrow) char [buffer_size];
		if (check == nullptr)
			errx( "nullptr on obtain_password\n" );
#ifdef __SSC_MemoryLocking__
		lock_os_memory( check, buffer_size );
#endif
		while (true) {
			Terminal term;
			memset( password, 0, buffer_size );
			memset( check   , 0, buffer_size );
			pw_size         = term.get_pw( password, buffer_size - 1, 1, entry_prompt   );
			static_cast<void>(term.get_pw( check   , buffer_size - 1, 1, reentry_prompt ));
			if (memcmp( password, check, buffer_size ) == 0)
				break;
			term.notify( "Passwords don't match." );
		}
		zero_sensitive( check, buffer_size );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( check, buffer_size );
#endif
		delete[] check;
		return pw_size;
	}

	void
	supplement_entropy (CSPRNG_t &csprng) {
		using namespace std;
		u8_t	hash	[Block_Bytes];
		char	input	[Max_Entropy_Chars + 1];
		Skein_t	skein;
		int	num_input_chars;
#ifdef __SSC_MemoryLocking__
		lock_os_memory( hash , sizeof(hash)  );
		lock_os_memory( input, sizeof(input) );
#endif
		num_input_chars = obtain_password( input, Entropy_Prompt, sizeof(input) );

		static_assert (Skein_t::State_Bytes == sizeof(hash));
		skein.hash_native( hash, reinterpret_cast<u8_t *>(input), num_input_chars );
		csprng.reseed( hash, sizeof(hash) );

		zero_sensitive( hash , sizeof(hash)  );
		zero_sensitive( input, sizeof(input) );
#ifdef __SSC_MemoryLocking__
		unlock_os_memory( hash , sizeof(hash)  );
		unlock_os_memory( input, sizeof(input) );
#endif
	}
}/*namespace ssc::crypto_impl*/
