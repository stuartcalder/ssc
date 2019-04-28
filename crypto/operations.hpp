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
template< size_t Block_Bits >
void xor_block(void * block, const void * add)
{
  static_assert( (Block_Bits % 8 == 0), "Bits must be a multiple of bytes" );
  static constexpr const size_t Block_Bytes = Block_Bits / 8;
  if constexpr( Block_Bits == 128 )
  {
    auto first_dword = reinterpret_cast<uint64_t*>( block );
    auto second_dword = reinterpret_cast<const uint64_t*>( add );

    (*first_dword) ^= (*second_dword);
    (*(first_dword + 1)) ^= (*(second_dword + 1));
  }
  else if constexpr( Block_Bits == 256 )
  {
    auto first_dword = reinterpret_cast<uint64_t*>( block );
    auto second_dword = reinterpret_cast<const uint64_t*>( add );
    (*(first_dword)) ^= (*(second_dword));
    (*(first_dword + 1)) ^= (*(second_dword + 1));
    (*(first_dword + 2)) ^= (*(second_dword + 2));
    (*(first_dword + 3)) ^= (*(second_dword + 3));
  }
  else if constexpr( Block_Bits == 512 )
  {
    auto first_dword  = reinterpret_cast<uint64_t*>( block );
    auto second_dword = reinterpret_cast<const uint64_t*>( add );
    (*(first_dword)) ^= (*(second_dword));
    (*(first_dword + 1)) ^= (*(second_dword + 1));
    (*(first_dword + 2)) ^= (*(second_dword + 2));
    (*(first_dword + 3)) ^= (*(second_dword + 3));
    (*(first_dword + 4)) ^= (*(second_dword + 4));
    (*(first_dword + 5)) ^= (*(second_dword + 5));
    (*(first_dword + 6)) ^= (*(second_dword + 6));
    (*(first_dword + 7)) ^= (*(second_dword + 7));
  }
  else if constexpr( (Block_Bits > 512) && (Block_Bits % 64 == 0 ) )
  {
    auto first_dword  = reinterpret_cast<uint64_t*>( block );
    auto second_dword = reinterpret_cast<const uint64_t*>( add );
    for( size_t i = 0; i < (Block_Bits / 64); ++i ) {
      (*(first_dword + i)) ^= (*(second_dword + i));
    }
  }
  else
  {
    auto first_byte = reinterpret_cast<uint8_t*>( block );
    auto second_byte = reinterpret_cast<const uint8_t*>( add );
    for( size_t i = 0; i < Block_Bytes; ++i ) {
      (*(first_byte + i)) ^= (*(second_byte + i));
    }
  }
}

void generate_random_bytes( void * const buffer, size_t num_bytes );
