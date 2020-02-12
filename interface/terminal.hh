/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include <cstdint>
#include <cstring>

#include <ssc/general/symbols.hh>
#include <ssc/crypto/operations.hh>

#if 0
namespace ssc {
	class DLL_PUBLIC Terminal {
		public:
        /* CONSTRUCTORS */
			Terminal();
			~Terminal();
        // Returns password size
			int get_pw(char    * buffer,
				   int const max_pw_size,
				   int const min_pw_size,
				   char const * prompt);
			void notify(char const * notice);
		private:
#if    defined (__UnixLike__)
			int DLL_LOCAL std_height;
			int DLL_LOCAL std_width;
#elif !defined (__Win64__)
#	error 'Unsupported OS'
#endif
    };/*class ssc::Terminal*/
}/*namespace ssc*/
#endif

namespace ssc {
	class DLL_PUBLIC Terminal {
		public:
			Terminal();
			~Terminal();
			template <int Buffer_Size>
			int get_sensitive_string (char	     *buffer,
					          char const *prompt);
		private:
	}; /*class ssc::Terminal*/

	template <int Buffer_Size>
	int Terminal::get_sensitive_string (char       *buffer,
					    char const *prompt)
	{
		using namespace std;
		// Password can be at most the size of the buffer minus one, to not include the null terminator.
		_CTIME_CONST(int) Max_Password_Size = Buffer_Size - 1;
#if    defined (__UnixLike__)
		cbreak();
		noecho();
		keypad( stdscr, TRUE );
		int index = 0;
		WINDOW *w = newwin( 5, Max_Password_Size, 0, 0 );
		// Enable special characters in the new window `w`.
		keypad( w, TRUE );
		bool outer, inner;
		outer = true;
		while (outer) {
			memset( buffer, 0, Buffer_Size );
			wclear( w );
			wmove( w, 1, 0 );
			waddstr( w, prompt );
			inner = true;
			while (inner) {
				int ch = wgetch( w );
				switch (ch) {
					case (127):
					case (KEY_DC):
					case (KEY_LEFT):
					case (KEY_BACKSPACE):
						if (index > 0) {
							int y, x;
							getyx( w, y, x );
							wdelch( w );
							wmove( w, y, x - 1 );
							wrefresh( w );
							buffer[ --index ] = '\0';
						}
						break;
					case ('\n'):
					case (KEY_ENTER):
						inner = false;
						break;
					default:
						if (index <= Max_Password_Size - 1) {
							waddch( w, '*' );
							wrefresh( w );
							buffer[ index++ ] = static_cast<char>(ch);
						}
				} /* switch (ch) */
			} /* while (inner) */
			outer = false;
		} /* while (outer) */
		int const password_size = strlen( buffer );
		delwin( w );
		return password_size;
#elif  defined (__Win64__)
#	error 'Not yet supported'
#else
#	error 'Unsupported OS'
#endif
	}
} /*namespace ssc*/
