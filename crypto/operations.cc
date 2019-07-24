#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>

#if   defined(__gnu_linux__)
    // Include unistd.h for getentropy()
    #include <unistd.h>
#elif defined(_WIN64)
    // Include for definitions of NTSUCCESS
    #include <ntdef.h>
    // Include bcrypt.h for BCryptGenRandom()
    #include <bcrypt.h>
#else
    #error "Currently operations.cc only implemented for Gnu/Linux and Microsoft Windows"
#endif

namespace ssc
{
    void generate_random_bytes(u8_t * const buffer, std::size_t num_bytes)
    {
        using namespace std;

#if   defined(__gnu_linux__)
        static constexpr auto const & Fail_String = "Failed to getentropy()";
        size_t offset = 0;
        while ( num_bytes >= 256 ) {
            if ( getentropy( (buffer + offset), 256 ) != 0 ) {
                fputs( Fail_String, stderr );
                exit   ( EXIT_FAILURE );
            }
            num_bytes -= 256;
            offset    += 256;
        }
        if ( getentropy( (buffer + offset), num_bytes ) != 0 ) {
            fputs( Fail_String, stderr );
            exit( EXIT_FAILURE );
        }
#elif defined(_WIN64)
        BCRYPT_ALG_HANDLE cng_provider_handle;
        // Open algorithm provider
        if ( BCryptOpenAlgorithmProvider( &cng_provider_handle, L"RNG", NULL, 0 ) != STATUS_SUCCESS ) {
            fputs( "BCryptOpenAlgorithmProvider() failed", stderr );
            exit( EXIT_FAILURE );
        }
        // Generate randomness
        if ( BCryptGenRandom( cng_provider_handle, buffer, num_bytes, 0 ) != STATUS_SUCCESS ) {
            fputs( "BCryptGenRandom() failed", stderr );
            exit( EXIT_FAILURE );
        }
        // Close algorithm provider
        if ( BCryptCloseAlgorithmProvider( cng_provider_handle, 0 ) != STATUS_SUCCESS ) {
            fputs( "BCryptCloseAlgorithmProvider() failed", stderr );
            exit( EXIT_FAILURE );
        }
#endif
    } /* ! generate_random_bytes */
    void zero_sensitive(void *buffer, std::size_t num_bytes)
    {
        using namespace std;

        explicit_bzero( buffer, num_bytes );
    }
} /* ! namespace ssc */
