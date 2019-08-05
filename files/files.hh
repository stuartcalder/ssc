#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>

#if defined( _WIN64 )
    #include <windows.h>
#endif

#define DLL_API
#if defined( _WIN32 )
    #if defined( BUILD_DLL )
        #define DLL_API __declspec(dllexport)
    #else
        #define DLL_API __declspec(dllimport)
    #endif
#endif


namespace ssc
{
#if   defined( __gnu_linux__ )
    DLL_API std::size_t get_file_size    (int const file_d);
#elif defined( _WIN64 )
    DLL_API std::size_t get_file_size    (HANDLE handle);
#endif
    DLL_API std::size_t get_file_size    (char const        * filename);
    DLL_API std::size_t get_file_size    (std::FILE const   * const file);
    DLL_API bool   file_exists           (char const        * filename);
    DLL_API void   check_file_name_sanity(std::string const & str,
                                          std::size_t const   min_size);
    DLL_API void   enforce_file_existence(char const * const __restrict filename,
                                          bool const                    force_to_exist,
                                          char const * const __restrict opt_error_msg = nullptr);
}
