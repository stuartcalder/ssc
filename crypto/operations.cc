#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/error_conditions.hh>

#if   defined( __gnu_linux__ )
    // Include unistd.h for getentropy()
    #include <unistd.h>
#elif defined( _WIN64 )
    // Include as the base for win32 crap
    #include <windows.h>
    // Include for definitions of NTSUCCESS
    #include <ntstatus.h>
    #include <ntdef.h>
    // Include bcrypt.h for BCryptGenRandom()
    #include <bcrypt.h>
#else
    #error "Currently operations.cc only implemented for Gnu/Linux and 64-bit Microsoft Windows"
#endif

namespace ssc
{
    void generate_random_bytes(u8_t * const buffer, std::size_t num_bytes)
    {
        using namespace std;

#if   defined( __gnu_linux__ )
        static constexpr auto const & Fail_String = "Failed to getentropy()\n";
        size_t offset = 0;
        while ( num_bytes >= 256 )
        {
            if ( getentropy( (buffer + offset), 256 ) != 0 )
            {
#if 0
                fputs( Fail_String, stderr );
                exit   ( EXIT_FAILURE );
#endif
                die_fputs( Fail_String );
            }
            num_bytes -= 256;
            offset    += 256;
        }
        if ( getentropy( (buffer + offset), num_bytes ) != 0 )
        {
#if 0
            fputs( Fail_String, stderr );
            exit( EXIT_FAILURE );
#endif
            die_fputs( Fail_String );
        }
#elif defined( _WIN64 )
        BCRYPT_ALG_HANDLE cng_provider_handle;
        // Open algorithm provider
        if ( BCryptOpenAlgorithmProvider( &cng_provider_handle, L"RNG", NULL, 0 ) != STATUS_SUCCESS )
        {
#if 0
            fputs( "BCryptOpenAlgorithmProvider() failed\n", stderr );
            exit( EXIT_FAILURE );
#endif
            die_fputs( "BCryptOpenAlgorithmProvider() failed\n" );
        }
        // Generate randomness
        if ( BCryptGenRandom( cng_provider_handle, buffer, num_bytes, 0 ) != STATUS_SUCCESS )
        {
#if 0
            fputs( "BCryptGenRandom() failed\n", stderr );
            exit( EXIT_FAILURE );
#endif
            die_fputs( "BCryptGenRandom() failed\n" );
        }
        // Close algorithm provider
        if ( BCryptCloseAlgorithmProvider( cng_provider_handle, 0 ) != STATUS_SUCCESS )
        {
#if 0
            fputs( "BCryptCloseAlgorithmProvider() failed\n", stderr );
            exit( EXIT_FAILURE );
#endif
            die_fputs( "BCryptCloseAlgorithmProvider() failed\n" );
        }
#else
    #error "ssc::generate_random_bytes only defined for Gnu/Linux and MS Windows"
#endif
    } /* ! generate_random_bytes */
    void zero_sensitive(void *buffer, std::size_t num_bytes)
    {
        using namespace std;

#if   defined( __gnu_linux__ )
        explicit_bzero( buffer, num_bytes );
#elif defined( _WIN64 )
        SecureZeroMemory( buffer, num_bytes );
#else
    #error "ssc::zero_sensitive defined for Gnu/Linux and MS Windows"
#endif
    } /* ! zero_sensitive */
} /* ! namespace ssc */
