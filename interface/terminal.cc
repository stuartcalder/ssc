#include <ssc/interface/terminal.hh>

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
void Terminal::get_password(char * const pw_buffer,
                            const int max_pw_size)
{
    using namespace std;

    char first_buf [ max_pw_size + 1 ];
    char second_buf[ max_pw_size + 1 ];
    int index = 0;
    char mpl[ 3 ];
    snprintf( mpl, sizeof(mpl), "%d", max_pw_size );
    WINDOW * w = newwin( 5, max_pw_size, 0, 0 );
    keypad( w, TRUE );
    for (;;) {
        memset( first_buf , 0, sizeof(first_buf) );
        memset( second_buf, 0, sizeof(second_buf) );
        wclear( w );
        wmove( w, 1, 0 );
        waddstr( w, "Please input a password (max length " );
        waddstr( w, mpl );
        waddstr( w, " characters)\n> " );
        for (;;) {
            int ch = wgetch( w );
            switch ( ch ) {
                case 127:
                case KEY_DC:
                case KEY_LEFT:
                case KEY_BACKSPACE:
                    if (index > 0) {
                        int y, x;
                        getyx( w, y, x );
                        wdelch( w );
                        wmove( w, y, x - 1 );
                        wrefresh( w );
                        --index;
                        first_buf[ index ] = '\0';
                    }
                    break;
                case KEY_ENTER:
                case '\n':
                    goto got_a_password;
                default:
                    if (index <= max_pw_size - 1) {
                        waddch( w, '*' );
                        wrefresh( w );
                        first_buf[ index ] = static_cast<char>( ch );
                        ++index;
                    }
                    break;
            }
        }
got_a_password:
        waddstr( w, "\nPlease input password a second time\n> " );
        index = 0;
        for (;;) {
            int ch = wgetch( w );
            switch ( ch ) {
                case 127:
                case KEY_DC:
                case KEY_LEFT:
                case KEY_BACKSPACE:
                    if (index > 0) {
                        int y, x;
                        getyx( w, y, x );
                        wmove( w, y, x - 1 );
                        wdelch( w );
                        wrefresh( w );
                        --index;
                        second_buf[ index ] = '\0';
                    }
                    break;
                case KEY_ENTER:
                case '\n':
                    goto second_password;
                default:
                    if (index <= max_pw_size - 1) {
                        waddch( w, '*' );
                        wrefresh( w );
                        second_buf[ index ] = static_cast<char>( ch );
                        ++index;
                    }
                    break;
            }
        }
second_password:
        if ( index == 0 ) {
            wclear( w );
            wmove( w, 0, 0 );
            waddstr( w, "0-Length passwords disallowed.\n" );
            wrefresh( w );
            wgetch( w );
            index = 0;
            continue;
        }
        else if ( memcmp( first_buf, second_buf, sizeof(first_buf) ) != 0 ) {
            wclear( w );
            wmove( w, 0, 0 );
            waddstr( w, "Input passwords do not seem to match...\n" );
            wrefresh( w );
            wgetch( w );
            index = 0;
            continue;
        }
        else {
            const int password_size = strlen( first_buf );
            strncpy( pw_buffer, first_buf, password_size + 1 );
            zero_sensitive( first_buf, sizeof(first_buf) );
            zero_sensitive( second_buf, sizeof(second_buf) );
        }
        break;
    }
    delwin( w );
}

#if 0
void Terminal::get_string(char * chr_buffer,
                          const int buffer_size,
                          const int min_input_size,
                          const char * prompt,
                          const bool censor_input)
{
    using namespace std;

    int index = 0;
    WINDOW * w = newwin( 5, buffer_size + 1, 0, 0 );
    keypad( w, TRUE );
    while ( true ) {
        memset( chr_buffer, 0, buffer_size );
        wclear( w );
        wmove( w, 1, 0 );
        waddstr( w, prompt );
        while ( true ) {
            int ch = wgetch( w );
            switch ( ch ) {
                case 127:
                case KEY_DC:
                case KEY_BACKSPACE:
                    if ( index > 0 ) {
                        int y, x;
                        getyx( w, y, x );
                        wdelch( w );
                        wmove( w, y, x - 1 );
                        wrefresh( w );
                        --index;
                        chr_buffer[ index ] = '\0';
                    }
                    break;
                case KEY_ENTER:
                case '\n':
                    goto got_newline;
                default:
                    if ( index <= buffer_size ) {
                        if ( censor_input )
                            waddch( w, '*' );
                        else
                            waddch( w, static_cast<char>( ch ) );
                        wrefresh( w );
                        chr_buffer[ index ] = static_cast<char>( ch );
                        ++index;
                    }
                    break;
            }
        }
got_newline:
        if ( index < min_input_size ) {
            wclear( w );
            wmove( w, 0, 0 );
            char s[ 4 ];
            snprintf( s, sizeof(s), "%d", min_input_size );
            waddstr( w, "Minimum of " );
            waddstr( w, s );
            waddstr( w, " characters needed!\n" );
            wrefresh( w );
            wgetch( w );
            index = 0;
            continue;
        }
        else {
            :
        }
        break;
    }
}
#endif
