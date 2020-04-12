/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

/* C Libraries */
#include <cstdint>
#include <cstdlib>
#include <cstring>
/* SSC Libraries */
#include <ssc/general/macros.hh>
#include <ssc/crypto/operations.hh>
/* OS-Conditional Libraries */
#if    defined (__UnixLike__)
#	include <ncurses.h>
#elif  defined (__Win64__)
#	include <ssc/general/error_conditions.hh>
#	include <windows.h>
#	include <conio.h>
#else
#	error 'Unsupported OS'
#endif

namespace ssc
{
	class _PUBLIC Terminal
	{
		public:
			using Char_t = u8_t;
			Terminal()
			{
#if    defined (__UnixLike__)
				initscr();
				getmaxyx( stdscr, std_height, std_width );
				clear();
#elif  defined (__Win64__)
				system( "cls" );
#else
#	error 'Unsupported OS'
#endif
			} /* Terminal() */
			~Terminal()
			{
#if    defined (__UnixLike__)
				endwin();
#elif  defined (__Win64__)
				system( "cls" );
#else
#	error 'Unsupported OS'
#endif
			} /* ~Terminal() */
			template <int Buffer_Size>
			int get_sensitive_string (_RESTRICT (Char_t *)     buffer,
					          _RESTRICT (char const *) prompt);
			inline void notify (char const *notice);
		private:
#ifdef __UnixLike__
			int std_height;
			int std_width;
#endif
	}; /*class ssc::Terminal*/

	/* template <int>
	 * get_sensitive_string (buffer,prompt)
	 *
	 * 	Get a string as user input from the keyboard, and do not echo the user's input to the screen.
	 * 	The size of the string (minus the null terminator) is returned as an int.
	 */
	template <int Buffer_Size>
	int Terminal::get_sensitive_string (_RESTRICT (Char_t *)     buffer,
					    _RESTRICT (char const *) prompt)
	{
		using namespace std;
		static_assert (Buffer_Size >= 2);
		_CTIME_CONST(int) Max_Password_Size = Buffer_Size - 1; // Password can be at most the size of the buffer minus one, to not include the null terminator.
#if    defined (__UnixLike__)
		cbreak(); // Disable line buffering.
		noecho(); // Disables echoing input.
		keypad( stdscr, TRUE ); // Enable keypad of the user's terminal.
		int index = 0; // Track the index of the current character.
		WINDOW *w = newwin( 5, Max_Password_Size, 0, 0 ); // Create a new window with 5 lines and Max_Password_Size columns, start at the top left (0,0).
		keypad( w, TRUE ); // Enable special characters in the new window `w`.
		bool outer, inner; // Two bools to track the following input loops.
		outer = true;
		while (outer) {
			memset( buffer, 0, Buffer_Size ); // Zero out the buffer to start.
			wclear( w ); // Screen `w` is cleared completely.
			wmove( w, 1, 0 ); // Move the cursor of `w` to line 1, column 0.
			waddstr( w, prompt ); // Add the C string `prompt` to `w`.
			inner = true;
			while (inner) {
				int ch = wgetch( w ); // Read a character from the window `w`.
				switch (ch) {
					// If a delete character was input...
					case (127):
					case (KEY_DC):
					case (KEY_LEFT):
					case (KEY_BACKSPACE):
						// ...and we're not already pointing at the first character...
						if (index > 0) {
							int y, x;
							getyx( w, y, x ); // Get the cursor position into y, x.
							wdelch( w ); // Delete the character at the current cursor position.
							wmove( w, y, x - 1 ); // Move the cursor back one column by 1.
							wrefresh( w ); // Update the visuals of the terminal.
							buffer[ --index ] = static_cast<Char_t>('\0'); // Move the index back 1, and null the character at that position.
							// `index` always points to an "unoccupied" space.
						}
						break;
					// Else if return was input...
					case ('\n'):
					case (KEY_ENTER):
						inner = false; // The user is done inputting. Kill the inner loop.
						break;
					// For all other inputs...
					default:
						// ...given that the index points to a position within allowed limits...
						if (index < Max_Password_Size) {
							waddch( w, '*' ); // Add an asterisk at the current cursor position and advance the cursor.
							wrefresh( w ); // Update the visuals of the terminal.
							buffer[ index++ ] = static_cast<Char_t>(ch); // Set the current indexed position to the input character and advance the index.
						}
				} /* switch (ch) */
			} /* while (inner) */
			outer = false; // Kill the outer loop.
		} /* while (outer) */
		// The buffer should now contain a null-terminated C-string.
		int const password_size = strlen( reinterpret_cast<char const*>(buffer) ); // Get the size of the null-terminated C-string in the buffer.
		delwin( w ); // Delete the window `w`.
		return password_size; // Return the number of non-null characters of the C-string in the buffer.
#elif  defined (__Win64__)
		int index = 0;
		bool repeat_ui, repeat_input;
		repeat_ui = true;
		while (repeat_ui) {
			memset( buffer, 0, Buffer_Size );
			system( "cls" );
			if (_cputs( prompt ) != 0)
				errx( "Error: Failed to _cputs()\n" );
			repeat_input = true;
			while (repeat_input) {
				int ch = _getch();
				switch (ch) {
					// A password character wkey was pushed.
					default:
						if ((index < Buffer_Size) && (ch >= 32) && (ch <= 126)) {
							if (_putch( '*' ) == EOF)
								errx( "Error: Failed to _putch()\n" );
							buffer[ index++ ] = static_cast<Char_t>(ch);
						}
						break;
					// Backspace was pushed.
					case ('\b'):
						if (index > 0) {
							if (_cputs( "\b \b" ) != 0)
								errx( "Error: Failed to _cputs()\n" );
							buffer[ --index ] = static_cast<Char_t>('\0');
						}
						break;
					// Enter was pushed.
					case ('\r'):
						repeat_input = false;
						break;
				} /* switch (ch) */
			} /* while (repeat_input) */
			repeat_ui = false;
		} /* while (repeat_ui) */
		int const password_size = strlen( reinterpret_cast<Char_t const*>(buffer) );
		system( "cls" );
		return password_size;
#else
#	error 'Unsupported OS'
#endif
	} /* get_sensitive_string(buffer,prompt) */
	void Terminal::notify (char const *notice)
	{
		using namespace std;
#if    defined (__UnixLike__)
		WINDOW *w = newwin( 1, strlen( notice ) + 1, 0, 0 );
		wclear( w );
		wmove( w, 0, 0 );
		waddstr( w, notice );
		wrefresh( w );
		wgetch( w );
		delwin( w );
#elif  defined (__Win64__)
		system( "cls" );
		if (_cputs( notice ) != 0)
			errx( "Error: Failed to _cputs()\n" );
		system( "pause" );
		system( "cls" );
#else
#	error 'Unsupported OS'
#endif
	} /* notify(notice) */

#if    defined (__UnixLike__)
#	define NEW_LINE "\n"
#elif  defined (__Win64__)
#	define NEW_LINE "\n\r"
#else
#	error 'Unsupported OS'
#endif
	template <int Buffer_Size>
	int obtain_password (_RESTRICT (u8_t *)       password_buffer,
			     _RESTRICT (char const *) entry_prompt,
			     int const                min_pw_size = 1,
			     int const                max_pw_size = Buffer_Size - 1)
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
	}
	template <int Buffer_Size>
	int obtain_password (_RESTRICT (u8_t *)       password_buffer,
			     _RESTRICT (u8_t *)       check_buffer,
			     _RESTRICT (char const *) entry_prompt,
			     _RESTRICT (char const *) reentry_prompt,
			     int const                min_pw_size = 1,
			     int const                max_pw_size = Buffer_Size - 1)
	{
		using namespace std;
		int size;
		while (true) {
			Terminal term;
			size = term.get_sensitive_string<Buffer_Size>( password_buffer, entry_prompt );
			if (size < min_pw_size) {
				term.notify( "Password is not long enough." NEW_LINE );
				continue;
			} else if (size > max_pw_size) {
				term.notify( "Password is too long." NEW_LINE );
				continue;
			}
			static_cast<void>(term.get_sensitive_string<Buffer_Size>( check_buffer, reentry_prompt ));
			if (memcmp( password_buffer, check_buffer, Buffer_Size ) == 0)
				break;
			term.notify( "Passwords do not match." NEW_LINE );
		}
		return size;
	}
} /*namespace ssc*/
#undef NEW_LINE
