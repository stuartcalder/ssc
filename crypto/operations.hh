/* operations.hh
 * No operating-system specific code here
 */
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/error_conditions.hh>

extern "C"
{
#if   defined( __gnu_linux__ )
    #include <unistd.h>
#elif defined( _WIN64 )
    #include <windows.h>
    #include <ntstatus.h>
    #include <bcrypt.h>
#else
    #error "Operations.hh only implemented for Gnu/Linux and 64-bit Microsoft Windows"
#endif
}/* ! extern "C" */

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
        if constexpr(Block_Bits == 128)
        {
            auto first_dword = reinterpret_cast<u64_t*>(block);
            auto second_dword = reinterpret_cast<const u64_t*>(add);

            static_assert(Block_Bits / 64 == 2);
            (*first_dword) ^= (*second_dword);
            (*(first_dword + 1)) ^= (*(second_dword + 1));
        }
        else if constexpr(Block_Bits == 256)
        {
            auto first_dword = reinterpret_cast<u64_t*>(block);
            auto second_dword = reinterpret_cast<const u64_t*>(add);

            static_assert(Block_Bits / 64 == 4);
            (*(first_dword)) ^= (*(second_dword));
            (*(first_dword + 1)) ^= (*(second_dword + 1));
            (*(first_dword + 2)) ^= (*(second_dword + 2));
            (*(first_dword + 3)) ^= (*(second_dword + 3));
        }
        else if constexpr(Block_Bits == 512)
        {
            auto first_dword  = reinterpret_cast<u64_t*>(block);
            auto second_dword = reinterpret_cast<const u64_t*>(add);

            static_assert(Block_Bits / 64 == 8);
            (*(first_dword    )) ^= (*(second_dword    ));
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
            u8_t       * first_byte = static_cast<u8_t *>(block);
            u8_t const * second_byte = static_cast<u8_t const *>(add);
            for ( std::size_t i = 0; i < Block_Bytes; ++i )
                (*(first_byte + i)) ^= (*(second_byte + i));
        }
    }/* ! xor_block */
    inline void generate_random_bytes(u8_t * buffer, std::size_t num_bytes)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        static constexpr auto const Max_Bytes = 256;
        while ( num_bytes >= Max_Bytes )
        {
            if ( getentropy( buffer, Max_Bytes ) != 0 )
                die_fputs( "Failed to getentropy()\n" );
            num_bytes -= Max_Bytes;
            buffer    += Max_Bytes;
        }
        if ( getentropy( buffer, num_bytes ) != 0 )
            die_fputs( "Failed to getentropy()\n" );
#elif defined( _WIN64 )
        BCRYPT_ALG_HANDLE cng_provider_handle;
        // Open algorithm provider
        if ( BCryptOpenAlgorithmProvider( &cng_provider_handle, L"RNG", NULL, 0 ) != STATUS_SUCCESS )
            die_fputs( "BCryptOpenAlgorithmProvider() failed\n" );
        // Generate randomness
        if ( BCryptGenRandom( cng_provider_handle, buffer, num_bytes, 0 ) != STATUS_SUCCESS )
            die_fputs( "BCryptGenRandom() failed\n" );
        // Close algorithm provider
        if ( BCryptCloseAlgorithmProvider( cng_provider_handle, 0 ) != STATUS_SUCCESS )
            die_fputs( "BCryptCloseAlgorithmProvider() failed\n" );
#else
    #error "ssc::generate_random_bytes defined for Gnu/Linux and MS Windows"
#endif
    }/* ! ssc::generate_random_bytes( ... ) */
    inline void zero_sensitive(void * buffer, std::size_t num_bytes)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        explicit_bzero( buffer, num_bytes );
#elif defined( _WIN64 )
        SecureZeroMemory( buffer, num_bytes );
#else
    #error "ssc::zero_sensitive defined for Gnu/Linux and MS Windows"
#endif
    }/* ! ssc::zero_sensitive( ... ) */
}/* ! namespace ssc */
