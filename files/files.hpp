#ifndef FILES_HPP
#define FILES_HPP
#include <cstdio>

namespace Files
{
  size_t get_file_size( FILE *stream )
  {
    size_t num_bytes = 0;
    while( std::fgetc( stream ) != EOF )
      ++num_bytes;
    std::rewind( stream );
    return num_bytes;
  }
}

#endif
