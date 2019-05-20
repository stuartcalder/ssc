#pragma once
#ifndef __gnu_linux__
    #error "Only defined for Gnu/Linux!"
#endif

#include <ssc/crypto/operations.hh>

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
    void get_password(char * pw_buffer,
                      const int max_pw_size);
private:
    int __std_height;
    int __std_width;
};
