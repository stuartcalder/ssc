/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <memory>

#include <ssc/general/symbols.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/interface/terminal.hh>
#include <ssc/memory/os_memory_locking.hh>

#if defined(__Unix_Like__)
#	include <ncurses.h>
#elif defined(_WIN64)
#	ifndef WIN64_WINDOWS_H
#		include <windows.h>
#		define WIN64_WINDOWS_H
#	endif

#	ifndef WIN64_CONIO_H
#		include <conio.h>
#		define WIN64_CONIO_H
#	endif
#else
#	error "ssc/interface/terminal.cc only defined for OpenBSD, GNU/Linux, and 64-bit MS Windows"
#endif

namespace ssc {
	Terminal::Terminal (void) {
#if defined(__Unix_Like__)
		initscr();
		getmaxyx( stdscr, std_height, std_width );
		clear();
#elif defined(_WIN64)
		system( "cls" );
#else
#	error "ssc::Terminal() only defined for OpenBSD, GNU/Linux and MS Windows"
#endif
	}/*ssc::Terminal::Terminal{}*/
	Terminal::~Terminal (void) {
#if defined(__Unix_Like__)
		endwin();
#elif defined(_WIN64)
		system( "cls" );
#else
#	error "ssc::~Terminal() only defined for OpenBSD, GNU/Linux, and MS Windows"
#endif
	}/*ssc::Terminal::~Terminal{}*/
	int
	Terminal::get_pw(char    * pw_buffer,
			 int const max_pw_size,
			 int const min_pw_size,
			 char const * prompt) {
		using namespace std;
#if defined(__Unix_Like__)
		// Screen setup
		cbreak();               // Disable line buffering
		noecho();               // Disable echoing
		keypad( stdscr, TRUE ); // Enable special characters
		// Buffer and index setup
		auto const buffer_size = max_pw_size + 1;
		auto buffer = std::make_unique<char[]>( buffer_size );
#ifdef __SSC_memlocking__
		lock_os_memory( buffer.get(), buffer_size );
#endif
		int index = 0;                  // Start from the beginning
		char mpl [4] = { 0 };           // max password length c-string
		snprintf( mpl, sizeof(mpl), "%d", max_pw_size );
		// Create a new blank window `w`
		WINDOW *w = newwin( 5, max_pw_size, 0, 0 );
		// Enable special characters in the new window `w`
		keypad( w, TRUE );
		bool outer, inner;
		outer = true;
		while (outer) {
			memset( buffer.get(), 0, buffer_size ); // Zero the buffer
			wclear( w );                         // Clear the new window
			wmove( w, 1, 0 );                    // Move the cursor into position
			waddstr( w, prompt );
			inner = true;
			// Input loop
			while( inner ) {
				int ch = wgetch( w );
				switch ( ch ) {
					case ( 127 ):
					case ( KEY_DC ):
					case ( KEY_LEFT ):
					case ( KEY_BACKSPACE ):
						if ( index > 0 ) {
							int y, x;
							getyx( w, y, x );
							wdelch( w );
							wmove( w, y, x - 1 );
							wrefresh( w );
							buffer[ --index ] = '\0';
						}
						break;
					case ( '\n' ):
					case ( KEY_ENTER ):
						inner = false;
						break;
					default:
						if ( index <= max_pw_size - 1 ) {
							waddch( w, '*' );
							wrefresh( w );
							buffer[ index++ ] = static_cast<char>(ch);
						}
				}
			}/* ! while( inner ) */
			if (index < min_pw_size) {
				constexpr auto char_arr_size = [](auto const &s) {
					return sizeof(s) - 1;
				};
				constexpr auto const & first  = "Minimum of ";
				constexpr auto const & second = " chracters needed!\n";
				char prompt[ char_arr_size( first )  + // all the chars of first
					     char_arr_size( second ) + // all the chars of second
					     3 +                       // 3 chars for min pw length
					     1 ] = { 0 };              // 0 null char
				snprintf( prompt, sizeof(prompt), "Minimum of %d characters needed!\n", min_pw_size );
				notify( prompt );
				continue;
			}/* ! if ( index < min_pw_size ) */
		outer = false;
		}/* ! while ( outer ) */
		int const password_size = strlen( buffer.get() );
		strncpy( pw_buffer, buffer.get(), password_size + 1 );
		zero_sensitive( buffer.get(), buffer_size );
#ifdef __SSC_memlocking__
		unlock_os_memory( buffer.get(), buffer_size );
#endif
		delwin( w );
		return password_size;
#elif defined(_WIN64)
		auto const buffer_size = max_pw_size + 1;
		auto buffer = std::make_unique<char[]>( buffer_size );
#ifdef __SSC_memlocking__
		lock_os_memory( buffer.get(), buffer_size );
#endif
		int index = 0;
		char mpl [4] = { 0 };
		snprintf( mpl, sizeof(mpl), "%d", max_pw_size );
		bool repeat_ui, repeat_input;
		repeat_ui = true;
		while (repeat_ui) {
			memset( buffer.get(), 0, buffer_size );
			system( "cls" );
			if (_cputs( prompt ) != 0)
				errx( "Error: Failed to _cputs()\n" );
			repeat_input = true;
			while (repeat_input) {
				int ch = _getch();
				switch (ch) {
					// A password character key was pushed
					default:
						if ((index <= max_pw_size - 1) &&
						    (ch >= 32) && (ch <= 126))
						{
							if (_putch( '*' ) == EOF)
								errx( "Error: Failed to _putch()\n" );
							buffer[ index++ ] = static_cast<char>(ch);
						}
						break;
					// Backspace was pushed
					case ( '\b' ):
						if (index > 0) {
							if (_cputs( "\b \b" ) != 0)
								errx( "Error: Failed to _cputs()\n" );
							buffer[ --index ] = '\0';
						}
						break;
					// Enter was pushed
					case ( '\r' ):
						repeat_input = false;
						break;
				}
			}/* ! while ( repeat_input ) */
			if ( index < min_pw_size ) {
				constexpr auto char_arr_size = [](auto const &s) {
					return sizeof(s) - 1;
				};
				constexpr auto const & first =   "Minimum of ";
				constexpr auto const & second = " characters needed!\r\n";
				char min_prompt	[char_arr_size(first)  + // all the chars of first
					     	 char_arr_size(second) + // all the chars of second
				                                     3 + // 3 chars for min pw length
				                                     1] = { 0 };// 0 null char
				snprintf( min_prompt, sizeof(min_prompt), "Minimum of %d characters needed!\r\n", min_pw_size );
				notify( min_prompt );
				continue;
			}/* ! if ( index < min_pw_size ) */
			repeat_ui = false;
		}/* ! while ( repeat_ui ) */
		int const password_size = strlen( buffer.get() );
		strncpy( pw_buffer, buffer.get(), password_size + 1 );
		zero_sensitive( buffer.get(), buffer_size );
#ifdef __SSC_memlocking__
		unlock_os_memory( buffer.get(), buffer_size );
#endif
		system( "cls" );
		return password_size;
#else
#	error "ssc::Terminal::get_pw(...) defined for OpenBSD, GNU/Linux, and MS Windows"
#endif
	}/* ! ssc::Terminal::get_pw */
    void Terminal::notify(char const *notice)
    {
        using namespace std;
#if defined(__Unix_Like__)
        WINDOW * w = newwin( 1, strlen(notice) + 1, 0, 0 );
        wclear( w );
        wmove( w, 0, 0 );
        waddstr( w, notice );
        wrefresh( w );
        wgetch( w );
        delwin( w );
#elif defined(_WIN64)
        system( "cls" );
	if (_cputs( notice ) != 0)
		errx( "Error: Failed to _cputs()\n" );
        system( "pause" );
        system( "cls" );
#else
#	error "ssc::Terminal::notify(...) defined for OpenBSD, GNU/Linux, and MS Windows"
#endif
    }/* ! ssc::Terminal::notify */
}
