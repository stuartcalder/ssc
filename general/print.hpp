#ifndef PRINT_HPP
#define PRINT_HPP
#include <cstdint>
#include <cstdio>

template< typename integral_t >
void print_integral_buffer( void * const i_buf, const size_t num_elements )
{
  using std::printf;
  static constexpr const auto& format_str = []( const size_t size ) {
    if( size == sizeof(unsigned char) )
      return "%2hhx,";
    else if( size == sizeof(unsigned short) )
      return "%2hx,";
    else if( size == sizeof( unsigned int) )
      return "%x,";
    else if( size == sizeof(unsigned long) )
      return "%8lx,";
    else if( size == sizeof(unsigned long long) )
      return "%8llx,";
    else if( size == sizeof(size_t) )
      return "%zx,";
    return "";
  }( sizeof(integral_t) );
  const integral_t * const alias = reinterpret_cast<const integral_t*>( i_buf );
  
  printf( "0x" );
  for( size_t i = 0; i < num_elements; ++i ) {
    printf( format_str, alias[i] );
  }
  printf( "\n" );
}

#endif
