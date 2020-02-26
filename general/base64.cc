/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#include <ssc/general/base64.hh>
#if 0

namespace ssc
{
    static char b64_r648_encode_six_bits(const uint8_t a)
    {
        if( a >= 0 && a <= 25 )
            return 'A' + a;
        else if( a >= 26 && a <= 51 )
            return 'a' + (a - 26);
        else if( a >= 52 && a <= 61 )
            return '0' + (a - 52);
        else if( a == 62 )
            return '+';
        return '/'; // true: a == 63
    }
    static uint8_t b64_r648_decode_six_bits(const char a)
    {
        if( a >= 'A' && a <= 'Z' ) {
            return 0 + (a - 'A');
        } else if( a >= 'a' && a <= 'z' ) {
            return 26 + (a - 'a');
        } else if( a >= '0' && a <= '9' ) {
            return 52 + (a - '0');
        } else if( a == '+' ) {
            return 62;
        } else { // true: a == '/'
            return 63;
        }
    }
    static int count_padding_chars(const char * const buffer, const int size)
    {
        int count = 0;
        for( int i = size - 1; i >= 0; --i ) {
            if( buffer[i] != '=' )
                break;
            ++count;
        }
        return count;
    }
    static void final_b64_r648_encode_eight_bits(const uint8_t in_bits, char * const out)
    {
        uint8_t first_six = in_bits >> 2,
            last_two = (in_bits & 0b00000011) << 4;
        out[0] = b64_r648_encode_six_bits( first_six );
        out[1] = b64_r648_encode_six_bits(  last_two );
        out[2] = '=';
        out[3] = '=';
    }
    static void final_b64_r648_decode_eight_bits(const char * const in_bits, uint8_t * out)
    {
        uint8_t first_six = b64_r648_decode_six_bits( in_bits[0] ) << 2,
            last_two  = b64_r648_decode_six_bits( in_bits[1] ) >> 4;
        out[0] = first_six | last_two;
    }
    static void final_b64_r648_encode_sixteen_bits(const uint8_t * const in, char * const out)
    {
        uint8_t first_six_in_0 = in[0] >> 2,
            last_two_in_0  = (in[0] & 0b00000011) << 4,
            first_four_in_1 = in[1] >> 4,
            last_four_in_1 = (in[1] & 0b00001111) << 2;
        out[0] = b64_r648_encode_six_bits( first_six_in_0 );
        out[1] = b64_r648_encode_six_bits( last_two_in_0 | first_four_in_1 );
        out[2] = b64_r648_encode_six_bits( last_four_in_1 );
        out[3] = '=';
    }
    static void final_b64_r648_decode_sixteen_bits(const char * const in, uint8_t * const out)
    {
        uint8_t first_decoded = b64_r648_decode_six_bits( in[0] ),
            second_decoded = b64_r648_decode_six_bits( in[1] ),
            third_decoded = b64_r648_decode_six_bits( in[2] );
        out[0] = (first_decoded << 2) | (second_decoded >> 4);
        out[1] = (second_decoded << 4) | (third_decoded >> 2);
    }
    static void b64_r648_encode_twentyfour_bits(const uint8_t * const in, char * const out)
    {
        uint8_t first_six_in_0 = in[0] >> 2,
            last_two_in_0  = (in[0] & 0b00000011) << 4,
            first_four_in_1 = in[1] >> 4,
            last_four_in_1 = (in[1] & 0b00001111) << 2,
            first_two_in_2 = in[2] >> 6,
            last_six_in_2 = in[2] & 0b00111111;
        out[0] = b64_r648_encode_six_bits( first_six_in_0 );
        out[1] = b64_r648_encode_six_bits( last_two_in_0 | first_four_in_1 );
        out[2] = b64_r648_encode_six_bits( last_four_in_1 | first_two_in_2 );
        out[3] = b64_r648_encode_six_bits( last_six_in_2 );
    }
    static void b64_r648_decode_twentyfour_bits(const char * const in, uint8_t * const out)
    {
        uint8_t encoded[4];
        for( int i = 0; i < static_cast<int>(sizeof(encoded)); ++i )
            encoded[i] = b64_r648_decode_six_bits( in[i] );
        
        out[0] = (encoded[0] << 2) | (encoded[1] >> 4);
        out[1] = (encoded[1] << 4) | (encoded[2] >> 2);
        out[2] = (encoded[2] << 6) | (encoded[3]     );
    }
    /* GLOBAL FUNCTIONS */
    constexpr size_t calculate_b64_r648_size( size_t size_in )
    {
        size_t count = 0;
        while( size_in > 3 ) {
            size_in -= 3;
            count   += 4; 
        }
        return count + 4;
    }
    
    void b64_r648_encode(const uint8_t * const in, char * const out, const size_t size_in)
    {
        const size_t number_24bit_chunks = size_in / 3;
        const size_t leftover_bytes_offset = number_24bit_chunks * 3;
        size_t input_offset  = 0,
            output_offset = 0;
        for( ; input_offset < leftover_bytes_offset; input_offset += 3, output_offset += 4 ) {
            b64_r648_encode_twentyfour_bits( in + input_offset, out + output_offset );
        }
        const size_t bytes_left = size_in - leftover_bytes_offset;
        switch( bytes_left ) {
        default:
            break;
        case( 1 ):
            final_b64_r648_encode_eight_bits( in[input_offset], out + output_offset );
            break;
        case( 2 ):
            final_b64_r648_encode_sixteen_bits( in + input_offset, out + output_offset );
            break;
        }
    }
    void b64_r648_decode(const char * const in, uint8_t * const out, const size_t size_in)
    {
        static constexpr const size_t Input_Quantum_Size =  4; // 4 encoded input bytes produce
        static constexpr const size_t Output_Quantum_Size = 3; // 3 plain output bytes
        const size_t last_input_quantum_offset = size_in - Input_Quantum_Size;
        const int padding_chars = count_padding_chars( in, size_in );
        size_t input_offset = 0,
            output_offset = 0;
        for( ; input_offset < last_input_quantum_offset;
             input_offset  += Input_Quantum_Size,
             output_offset += Output_Quantum_Size )
            {
                b64_r648_decode_twentyfour_bits( in + input_offset, out + output_offset );
            }
        switch( padding_chars ) {
        default:
            b64_r648_decode_twentyfour_bits( in + input_offset, out + output_offset );
            break;
        case( 1 ):
            final_b64_r648_decode_sixteen_bits( in + input_offset, out + output_offset );
            break;
        case( 2 ):
            final_b64_r648_decode_eight_bits( in + input_offset, out + output_offset );
            break;
        }
    }
}
#endif
