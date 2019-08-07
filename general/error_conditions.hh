#pragma once
#include <cstdlib>
#include <cstdio>

namespace ssc
{
    void die_fprintf(char const * die_message);
    void die_fputs(char const * die_message);
}
