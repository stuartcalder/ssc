#ifndef TESTING_HPP
#define TESTING_HPP
#include <cstdint>
#include <string>
#include <iostream>


std::string uint8_to_string( uint8_t u8 )
{
  auto nibble_to_hex_char = []( uint8_t a ) -> char {
    switch( a ) {
      case 0x0: return '0';
      case 0x1: return '1';
      case 0x2: return '2';
      case 0x3: return '3';
      case 0x4: return '4';
      case 0x5: return '5';
      case 0x6: return '6';
      case 0x7: return '7';
      case 0x8: return '8';
      case 0x9: return '9';
      case 0xa: return 'a';
      case 0xb: return 'b';
      case 0xc: return 'c';
      case 0xd: return 'd';
      case 0xe: return 'e';
      case 0xf: return 'f';
    }
  };
  std::string s;
  return ( s + nibble_to_hex_char( u8 >> 4 ) + nibble_to_hex_char( u8 & 0x0f ) );
}
void print_uint8_buffer( const uint8_t *buffer, const int size )
{
  using std::cout;
  cout << "0x";
  for( int i = 0; i < size; ++i )
    cout << uint8_to_string( buffer[i] );
  cout << "\n";
}

#endif
