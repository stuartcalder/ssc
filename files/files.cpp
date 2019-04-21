#include "files.hpp"

size_t get_file_size( std::FILE *stream )
{
  size_t num_bytes = 0;
  while( std::fgetc( stream ) != EOF )
    ++num_bytes;
  std::rewind( stream );
  return num_bytes;
}

void sanitize_file_name(std::string & str,
                        const size_t min_size)
{
  if( str.size() < min_size ) {
    std::fprintf( stderr, "Error: Filename %s must have at least %zu character(s)\n",
                  str.c_str(), min_size );
    exit( EXIT_FAILURE );
  }
}
