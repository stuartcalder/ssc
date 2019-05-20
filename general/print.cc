#include <ssc/general/print.hh>

void print_binary_buffer( const uint8_t * buffer, const size_t num_bytes )
{
  auto print_4_bits = [](uint8_t i)
  {
    switch( i ) {
      default:
      case( 0x0 ):
        std::printf( "0000" );
        break;
      case( 0x1 ):
        std::printf( "0001" );
        break;
      case( 0x2 ):
        std::printf( "0010" );
        break;
      case( 0x3 ):
        std::printf( "0011" );
        break;
      case( 0x4 ):
        std::printf( "0100" );
        break;
      case( 0x5 ):
        std::printf( "0101" );
        break;
      case( 0x6 ):
        std::printf( "0110" );
        break;
      case( 0x7 ):
        std::printf( "0111" );
        break;
      case( 0x8 ):
        std::printf( "1000" );
        break;
      case( 0x9 ):
        std::printf( "1001" );
        break;
      case( 0xa ):
        std::printf( "1010" );
        break;
      case( 0xb ):
        std::printf( "1011" );
        break;
      case( 0xc ):
        std::printf( "1100" );
        break;
      case( 0xd ):
        std::printf( "1101" );
        break;
      case( 0xe ):
        std::printf( "1110" );
        break;
      case( 0xf ):
        std::printf( "1111" );
        break;
    }
  };
  size_t i = 0;
  std::printf( "0b" );
  while( i < num_bytes ) {
    print_4_bits( buffer[i] >> 4 );
    print_4_bits( buffer[i] & 0b00001111 );
    std::putchar( ',' );
    ++i;
  }
  std::putchar( '\n' );
}
