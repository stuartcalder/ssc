#include <ssc/interface/terminal.hh>

namespace ssc
{
    Terminal::Terminal(bool buffer_chars,
                       bool echo_chars,
                       bool special_chars)
    {
        initscr();
        if ( ! buffer_chars )
            cbreak();
        if ( ! echo_chars )
            noecho();
        if ( special_chars )
            keypad( stdscr, TRUE );
        getmaxyx( stdscr, __std_height, __std_width );
        clear();
    }
    Terminal::~Terminal()
    {
        endwin();
    }
    void Terminal::get_pw(char     *pw_buffer,
                          const int max_pw_size,
                          const int min_pw_size)
    {
        using namespace std;
        char buffer[ max_pw_size + 1 ];
        int index = 0;
        char mpl[ 3 ];
        snprintf( mpl, sizeof(mpl), "%d", max_pw_size );
        WINDOW *w = newwin( 5, max_pw_size, 0, 0 );
        keypad( w, TRUE );
        bool outer, inner;
        outer = true;
        while ( outer ) {
            memset( buffer, 0, sizeof(buffer) );
            wclear( w );
            wmove( w, 1, 0 );
            waddstr( w, "Please input a password (max length " );
            waddstr( w, mpl );
            waddstr( w, " characters)\n> " );
            inner = true;
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
                        buffer[ index ] = static_cast<char>( ch );
                        ++index;
                    }
                }
            }
            if ( index < min_pw_size ) {
                constexpr auto char_arr_size = [](const auto &s)
                                               {
                                                   return sizeof(s) - 1;
                                               };
                constexpr const auto &first  = "Minimum of ";
                constexpr const auto &second = " chracters needed!\n";
                char prompt[ char_arr_size( first )  +    // all the chars of first
                             char_arr_size( second ) +   // all the chars of second
                             2 +                         // 2 chars for min pw length
                             1 ] = { 0 };                // 0 null char
                snprintf( prompt,
                          sizeof(prompt),
                          "Minimum of %d characters needed!\n",
                          min_pw_size );
                notify( prompt );
                continue;
            }
            outer = false;
        }
        const int password_size = strlen( buffer );
        strncpy( pw_buffer, buffer, password_size + 1 );
        zero_sensitive( buffer, sizeof(buffer) );
        delwin( w );
    }
}
