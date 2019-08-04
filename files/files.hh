#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>

#ifdef _WIN64
    #include <windows.h>
#endif

namespace ssc
{
#if   defined(__gnu_linux__)
    std::size_t get_file_size    (int const file_d);
#elif defined(_WIN64)
    std::size_t get_file_size    (HANDLE handle);
#endif
    std::size_t get_file_size    (char const        * filename);
    std::size_t get_file_size    (std::FILE const   * const file);
    bool   file_exists           (char const        * filename);
    void   check_file_name_sanity(std::string const & str,
                                  std::size_t const   min_size);
    void   enforce_file_existence(char const * const __restrict filename,
                                  bool const                    force_to_exist,
                                  char const * const __restrict opt_error_msg = nullptr);
}
