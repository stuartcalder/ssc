#pragma once
#include <cstdint>
#include <climits>
#include <unistd.h>

template< typename uint_t >
uint_t rotate_left( uint_t value, uint_t count )
{
  const uint_t mask = (CHAR_BIT * sizeof(uint_t)) - 1;
  count &= mask;
  return ( value << count ) | ( value >> (-count & mask));
}
template< typename uint_t >
uint_t rotate_right( uint_t value, uint_t count )
{
  const uint_t mask = (CHAR_BIT * sizeof(uint_t)) - 1;
  count &= mask;
  return ( value >> count ) | ( value << (-count & mask));
}

void generate_random_bytes( void * const buffer, size_t num_bytes );
