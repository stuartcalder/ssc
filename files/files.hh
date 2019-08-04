#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>

#define MS_API
#ifdef _WIN64
    #if defined( SSC_EXPORTS )
        #define MS_API __declspec(dllexport)
    #else
        #define MS_API __declspec(dllimport)
    #endif
#endif

namespace ssc
{
#if   defined(__gnu_linux__)
    MS_API std::size_t get_file_size    (int const file_d);
#elif defined(_WIN64)
    MS_API std::size_t get_file_size    (HANDLE handle);
#endif
    MS_API std::size_t get_file_size    (char const        * filename);
    MS_API std::size_t get_file_size    (std::FILE const   * const file);
    MS_API bool   file_exists           (char const        * filename);
    MS_API void   check_file_name_sanity(std::string const & str,
                                         std::size_t const   min_size);
    MS_API void   enforce_file_existence(char const * __restrict const filename,
                                         bool const                    force_to_exist,
                                         char const * __restrict const opt_error_msg = nullptr);
}
