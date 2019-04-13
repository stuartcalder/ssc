#include "print.hpp"

void print_char_buffer(const char * const c_buf, const size_t num_chars )
{
  for( size_t i = 0; i < num_chars; ++i )
    std::putchar( c_buf[i] );
}
