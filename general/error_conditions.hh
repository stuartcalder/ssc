#pragma once
#include <cstdio>
#include <cstdlib>
#include <ssc/general/symbols.hh>

namespace ssc
{
    inline void die_fprintf(char const * die_message)
    {
        std::fprintf( stderr, die_message );
        std::exit( EXIT_FAILURE );
    }
    inline void die_fputs(char const * die_message)
    {
        std::fputs( die_message, stderr );
        std::exit( EXIT_FAILURE );
    }
}/* ! namespace ssc */
