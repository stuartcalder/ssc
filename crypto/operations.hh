#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
#include <ssc/general/integers.hh>

#if defined(__gnu_linux__)
#include <unistd.h>
#else
#error "Only implemented for Gnu/Linux"
#endif

namespace ssc
{
    static_assert(CHAR_BIT == 8);
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
    template< std::size_t Block_Bits >
    void xor_block(void * __restrict block, const void * __restrict add)
    {
        static_assert( CHAR_BIT == 8 );
        static_assert( (Block_Bits % 8 == 0), "Bits must be a multiple of bytes" );
        static constexpr const std::size_t Block_Bytes = Block_Bits / 8;
        if      constexpr(Block_Bits == 128)
                             {
                                 auto first_dword = reinterpret_cast<u64_t*>(block);
                                 auto second_dword = reinterpret_cast<const u64_t*>(add);
                                 
                                 (*first_dword) ^= (*second_dword);
                                 (*(first_dword + 1)) ^= (*(second_dword + 1));
                             }
        else if constexpr(Block_Bits == 256)
                             {
                                 auto first_dword = reinterpret_cast<u64_t*>(block);
                                 auto second_dword = reinterpret_cast<const u64_t*>(add);
                                 (*(first_dword)) ^= (*(second_dword));
                                 (*(first_dword + 1)) ^= (*(second_dword + 1));
                                 (*(first_dword + 2)) ^= (*(second_dword + 2));
                                 (*(first_dword + 3)) ^= (*(second_dword + 3));
                             }
        else if constexpr(Block_Bits == 512)
                             {
                                 auto first_dword  = reinterpret_cast<u64_t*>(block);
                                 auto second_dword = reinterpret_cast<const u64_t*>(add);
                                 (*(first_dword))     ^= (*(second_dword));
                                 (*(first_dword + 1)) ^= (*(second_dword + 1));
                                 (*(first_dword + 2)) ^= (*(second_dword + 2));
                                 (*(first_dword + 3)) ^= (*(second_dword + 3));
                                 (*(first_dword + 4)) ^= (*(second_dword + 4));
                                 (*(first_dword + 5)) ^= (*(second_dword + 5));
                                 (*(first_dword + 6)) ^= (*(second_dword + 6));
                                 (*(first_dword + 7)) ^= (*(second_dword + 7));
                             }
        else if constexpr((Block_Bits > 512) && (Block_Bits % 64 == 0))
                             {
                                 auto first_dword  = reinterpret_cast<u64_t*>(block);
                                 auto second_dword = reinterpret_cast<const u64_t*>(add);
                                 for ( std::size_t i = 0; i < (Block_Bits / 64); ++i )
                                     (*(first_dword + i)) ^= (*(second_dword + i));
                             }
        else
            {
                auto first_byte = reinterpret_cast<u8_t*>(block);
                auto second_byte = reinterpret_cast<const u8_t*>(add);
                for ( std::size_t i = 0; i < Block_Bytes; ++i )
                    (*(first_byte + i)) ^= (*(second_byte + i));
            }
    }
    
    void generate_random_bytes(u8_t * const buffer,
                               std::size_t num_bytes);
    void zero_sensitive(void *buffer,
                        std::size_t num_bytes);
}
