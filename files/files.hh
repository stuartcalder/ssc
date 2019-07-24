#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>

namespace ssc
{
#if   defined(__gnu_linux__)
    std::size_t get_file_size    (const int file_d);
#elif defined(_WIN64)
    std::size_t get_file_size    ();//TODO
#endif
    std::size_t get_file_size    (const char        * filename);
    std::size_t get_file_size    (const std::FILE   * const file);
    bool   file_exists           (const char        * filename);
    void   check_file_name_sanity(const std::string & str,
                                  const std::size_t   min_size);
    void   enforce_file_existence(char const * const __restrict filename,
                                  bool const         force_to_exist,
                                  char const * const __restrict opt_error_msg = nullptr);
}
