#pragma once
#ifndef __gnu_linux__
    #error "Only defined for Gnu/Linux!"
#endif

#include <ssc/crypto/operations.hh>

#include <cstdint>
#include <cstring>
#include <ncurses.h>

namespace ssc
{
    class Terminal
    {
    public:
        /* CONSTRUCTORS */
        Terminal(bool buffer_chars,
                 bool echo_chars,
                 bool special_chars);
        ~Terminal();
        void get_password(char * pw_buffer,
                          const int max_pw_size);
#if 0
        void get_string(char * chr_buffer,
                        const int buffer_size,
                        const int min_input_size,
                        const char *prompt,
                        const bool censor_input = false);
#endif
        void get_pw(char     *pw_buffer,
                    const int max_pw_size,
                    const int min_pw_size);
        void notify(const char *notice);
    private:
        int __std_height;
        int __std_width;
    };
}
