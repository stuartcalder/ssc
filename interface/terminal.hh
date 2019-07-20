#pragma once
#if ! defined(__gnu_linux__)
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
        Terminal();
        ~Terminal();
        void get_pw(char     *pw_buffer,
                    const int max_pw_size,
                    const int min_pw_size);
        void notify(const char *notice);
    private:
        int std_height;
        int std_width;
    };
}
