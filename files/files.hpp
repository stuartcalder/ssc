#pragma once

#include <cstdlib>
#include <cstdio>
#include <string>

size_t get_file_size         (const char * filename);
bool   file_exists           (const char * filename);
void   check_file_name_sanity(const std::string & str,
                              const size_t min_size);
