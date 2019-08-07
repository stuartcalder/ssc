#include <cstdio>
#include <ssc/general/error_conditions.hh>

namespace ssc
{
    void die_fprintf(char const * die_message)
    {
        std::fprintf( stderr, die_message );
        std::exit( EXIT_FAILURE );
    }
    void die_fputs(char const * die_message)
    {
        std::fputs( die_message, stderr );
        std::exit( EXIT_FAILURE );
    }
}
