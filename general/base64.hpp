#ifndef BASE64_HPP
#define BASR64_HPP
#include <cstdint>
#include <cstring>

/*
 
   [76543210][76543210][76543210]   3 octets
   [543210][543210][543210][543210] 4 hextets
    54321054  32105432  10543210
    |         |         |
    |         |         3rd octet
    |         2nd octet
    first octet

 */
char b64_encode_six_bits( uint8_t a )
{
  if( a >= 0 && a <= 25 )
    return 'a' + a;
  else if( a >= 26 && a <= 51 )
    return 'a' + (a - 26);
  else if( a >= 52 && a <= 61 )
    return '0' + (a - 52);
  else if( a == 62 )
    return '+';
  else // a must equal 63 here
    return '/';
}
void b64_encode_twentyfour_bits( const uint8_t * const in, char * const out )
{
  uint8_t first_six_in_0 = in[0] >> 2,
          last_two_in_0  = (in[0] & 0b00000011) << 4,
          first_four_in_1 = in[1] >> 4,
          last_four_in_1 = (in[1] & 0b00001111) << 2,
          first_two_in_2 = in[2] >> 6,
          last_six_in_2 = in[2] & 0b00111111;
  out[0] = encode_six_bits( first_six_in_0 );
  out[1] = encode_six_bits( last_two_in_0 | first_four_in_1 );
  out[2] = encode_six_bits( last_four_in_1 | first_two_in_2 );
  out[3] = encode_six_bits( last_six_in_2 );
}

void binary_to_b64( const uint8_t * const in, uint8_t * const out, const size_t size_in )
{
}

#endif
