#include "/home/stuart/src/files/files.hpp"

int main()
{
  FILE *f = std::fopen( "/home/stuart/src/files/files.hpp", "rb" );
  std::printf( "%zu\n", Files::get_file_size( f ) );
  std::fclose( f );
  return 0;
}
