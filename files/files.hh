#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>
#include <ssc/general/symbols.hh>

#if defined( _WIN32 )
    #include <windows.h>
#endif

namespace ssc
{
#if   defined( __gnu_linux__ )
    DLL_PUBLIC std::size_t get_file_size    (int const file_d);
#elif defined( _WIN64 )
    DLL_PUBLIC std::size_t get_file_size    (HANDLE handle);
#endif
    DLL_PUBLIC std::size_t get_file_size    (char const        * filename);
    DLL_PUBLIC std::size_t get_file_size    (std::FILE const   * const file);
    DLL_PUBLIC bool   file_exists           (char const        * filename);
    DLL_PUBLIC void   check_file_name_sanity(std::string const & str,
                                             std::size_t const   min_size);
    DLL_PUBLIC void   enforce_file_existence(char const * const __restrict filename,
                                             bool const                    force_to_exist,
                                             char const * const __restrict opt_error_msg = nullptr);
}
