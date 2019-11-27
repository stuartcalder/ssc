/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <ssc/general/print.hh>

namespace ssc
{
    void print_binary_buffer( const uint8_t * buffer, const size_t num_bytes )
    {
        auto print_4_bits = [](u8_t i)
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
}/* ! namespace ssc */
