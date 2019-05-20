#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>

#ifdef __gnu_linux__
    size_t get_file_size         (const int file_d);
#endif
size_t get_file_size         (const char        * filename);
size_t get_file_size         (const std::FILE   * const file);
bool   file_exists           (const char        * filename);
void   check_file_name_sanity(const std::string & str,
                              const size_t min_size);
