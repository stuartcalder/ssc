#pragma once
#ifndef __gnu_linux__
    #error "Only defined for Gnu/Linux!"
#endif

#include <cstdint>
#include <cstring>
#include <ncurses.h>

class Terminal
{
public:
    /* CONSTRUCTORS */
    Terminal(bool buffer_chars,
             bool echo_chars,
             bool special_chars);
    ~Terminal();
    bool get_password(uint8_t * pw_buffer,
                      const int max_pw_size);
private:
    int __std_height;
    int __std_width;
};
