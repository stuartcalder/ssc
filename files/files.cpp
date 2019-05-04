#include "files.hpp"

#ifdef  __gnu_linux__
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <unistd.h>
#endif

size_t get_file_size(const char * filename)
{
  using namespace std;
#ifdef __gnu_linux__
  struct stat s;
  if( stat( filename, &s ) != 0 ) {
    fprintf( stderr, "Failed to stat info about %s\n", filename );
  }
  return static_cast<size_t>(s.st_size);
#else // All other platforms
  size_t num_bytes = 0;
  FILE stream = fopen( filename "rb" );
  while( fgetc( stream ) != EOF )
    ++num_bytes;
  rewind( stream );
  return num_bytes;
#endif
}

bool file_exists(const char * filename)
{
  using namespace std;
  bool exists = false;
  FILE * test = fopen( filename, "rb" );
  if( test != nullptr ) {
    fclose( test );
    exists = true;
  }
  return exists;
}

void check_file_name_sanity(const std::string & str,
                            const size_t min_size)
{
  if( str.size() < min_size ) {
    std::fprintf( stderr, "Error: Filename %s must have at least %zu character(s)\n",
                  str.c_str(), min_size );
    std::exit( EXIT_FAILURE );
  }
}
