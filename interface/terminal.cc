#include <cstdio>
#include <cstdlib>
#include <utility>
#include <memory>

#include <ssc/interface/terminal.hh>

#if   defined(__gnu_linux__)
    #include <ncurses.h>
#elif defined(_WIN64)
    #include <conio.h>
    #include <windows.h>
#endif

namespace ssc
{
    Terminal::Terminal()
    {
#if   defined(__gnu_linux__)
        initscr();
        getmaxyx( stdscr, std_height, std_width );
        clear();
#elif defined(_WIN64)
        system( "cls" );
#else
    #error "ssc::Terminal() only defined for Gnu/Linux and MS Windows"
#endif
    }/* ! ssc::Terminal::Terminal() */
    Terminal::~Terminal()
    {
#if   defined(__gnu_linux__)
        endwin();
#elif defined(_WIN64)
        system( "cls" );
#else
    #error "ssc::~Terminal() only defined for Gnu/Linux and MS Windows"
#endif
    }/* ! ssc::Terminal::~Terminal() */
    void Terminal::get_pw(char    * pw_buffer,
                          int const max_pw_size,
                          int const min_pw_size)
    {
        using namespace std;
#if   defined(__gnu_linux__)
        // Screen setup
        cbreak();               // Disable line buffering
        noecho();               // Disable echoing
        keypad( stdscr, TRUE ); // Enable special characters
        // Buffer and index setup
        char buffer[ max_pw_size + 1 ]; // Prepare to store `max_pw_size` chars
        int index = 0;                  // Start from the beginning
        char mpl[4] = { 0 };            // max password length c-string
        snprintf( mpl, sizeof(mpl), "%d", max_pw_size );
        // Create a new blank window `w`
        WINDOW *w = newwin( 5, max_pw_size, 0, 0 );
        // Enable special characters in the new window `w`
        keypad( w, TRUE );
        bool outer, inner;
        outer = true;
        while ( outer )
        {
            memset( buffer, 0, sizeof(buffer) ); // Zero the buffer
            wclear( w );                         // Clear the new window
            wmove( w, 1, 0 );                    // Move the cursor into position
            waddstr( w, "Please input a password (max length " );
            waddstr( w, mpl );
            waddstr( w, " characters)\n> " );
            inner = true;
            // Input loop
            while( inner )
            {
                int ch = wgetch( w );
                switch ( ch )
                {
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
                            buffer[ index++ ] = static_cast<char>( ch );
                        }
                }
            }/* ! while( inner ) */
            if ( index < min_pw_size )
            {
                constexpr auto char_arr_size = [](auto const &s)
                                               {
                                                   return sizeof(s) - 1;
                                               };
                constexpr auto const & first  = "Minimum of ";
                constexpr auto const & second = " chracters needed!\n";
                char prompt[ char_arr_size( first )  + // all the chars of first
                             char_arr_size( second ) + // all the chars of second
                             2 +                       // 2 chars for min pw length
                             1 ] = { 0 };              // 0 null char
                snprintf( prompt,
                          sizeof(prompt),
                          "Minimum of %d characters needed!\n",
                          min_pw_size );
                notify( prompt );
                continue;
            }/* ! if ( index < min_pw_size ) */
            outer = false;
        }/* ! while ( outer ) */
        int const password_size = strlen( buffer );
        strncpy( pw_buffer, buffer, password_size + 1 );
        zero_sensitive( buffer, sizeof(buffer) );
        delwin( w );
#elif defined(_WIN64)
#if 0
        char buffer [max_pw_size + 1];
#endif
        auto const buffer_size = max_pw_size + 1;
        auto buffer = std::make_unique<char[]>( buffer_size );
        int index = 0;
        char mpl [4] = { 0 };
        snprintf( mpl, sizeof(mpl), "%d", max_pw_size );
        bool repeat_ui, repeat_input;
        repeat_ui = true;
        while ( repeat_ui )
        {
            memset( buffer.get(), 0, buffer_size );
            system( "cls" );
            if ( _cputs( "Please input a password (max length " ) != 0 )
            {
                fputs( "Failed to _cputs\n", stderr );
                exit( EXIT_FAILURE );
            }
            if ( _cputs( mpl ) != 0 )
            {
                fputs( "Failed to _cputs\n", stderr );
                exit( EXIT_FAILURE );
            }
            if ( _cputs( " characters)\r\n> " ) != 0 )
            {
                fputs( "Failed to _cputs\n", stderr );
                exit( EXIT_FAILURE );
            }
            repeat_input = true;
            while ( repeat_input )
            {
                int ch = _getch();
                switch ( ch )
                {
                    // A password character key was pushed
                    default:
                        if ( (index <= max_pw_size - 1) &&
                                (ch >= 32) && (ch <= 126) )
                        {
                            if ( _putch( '*' ) == EOF )
                            {
                                fputs( "Failed to _putch\n", stderr );
                                exit( EXIT_FAILURE );
                            }
                            buffer[ index++ ] = static_cast<char>(ch);
                        }
                        break;
                    // Backspace was pushed
                    case ( '\b' ):
                        if ( index > 0 )
                        {
                            if ( _cputs( "\b \b" ) != 0 )
                            {
                                fputs( "Failed to _cputs\n", stderr );
                                exit( EXIT_FAILURE );
                            }
                            buffer[ --index ] = '\0';
                        }
                        break;
                    // Enter was pushed
                    case ( '\r' ):
                        repeat_input = false;
                        break;
                }
            }/* ! while ( repeat_input ) */
            if ( index < min_pw_size )
            {
                constexpr auto char_arr_size = [](auto const &s)
                {
                    return sizeof(s) - 1;
                };
                constexpr auto const & first = "Minimum of ";
                constexpr auto const & second = " characters needed!\r\n";
                char prompt [char_arr_size(first) + \ // all the chars of first
                             char_arr_size(second) + \ // all the chars of second
                             2 + \                     // 2 chars for min pw length
                             1] = { 0 };             // 0 null char
                snprintf( prompt,
                        sizeof(prompt),
                        "Minimum of %d characters needed!\r\n",
                        min_pw_size );
                notify( prompt );
                continue;
            }/* ! if ( index < min_pw_size ) */
            repeat_ui = false;
        }/* ! while ( repeat_ui ) */
        int const password_size = strlen( buffer.get() );
        strncpy( pw_buffer, buffer.get(), password_size + 1 );
        zero_sensitive( buffer.get(), buffer_size );
        system( "cls" );
#else
    #error "ssc::Terminal::get_pw(...) defined for Gnu/Linux and MS Windows"
#endif
    }/* ! ssc::Terminal::get_pw */
    void Terminal::notify(char const *notice)
    {
        using namespace std;
#if   defined(__gnu_linux__)
        WINDOW * w = newwin( 1, strlen(notice) + 1, 0, 0 );
        wclear( w );
        wmove( w, 0, 0 );
        waddstr( w, notice );
        wrefresh( w );
        wgetch( w );
        delwin( w );
#elif defined(_WIN64)
        system( "cls" );
        if ( _cputs( notice ) != 0 )
        {
            fputs( "Failed to _cputs\n", stderr );
            exit( EXIT_FAILURE );
        }
        system( "pause" );
        system( "cls" );
#else
    #error "ssc::Terminal::notify(...) defined for Gnu/Linux and MS Windows"
#endif
    }/* ! ssc::Terminal::notify */
}
