#include "operations.hpp"

void generate_random_bytes(uint8_t * const buffer, size_t num_bytes)
{
  size_t offset = 0;
  while( num_bytes >= 256 ) {
    getentropy( (buffer + offset), 256 );
    num_bytes -= 256;
    offset    += 256;
  }
  getentropy( (buffer + offset), num_bytes );
}
