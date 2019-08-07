#pragma once
#include <cstdlib>
#include <cstdio>
#include <ssc/general/symbols.hh>

namespace ssc
{
    DLL_PUBLIC void die_fprintf(char const * die_message);
    DLL_PUBLIC void die_fputs(char const * die_message);
}
