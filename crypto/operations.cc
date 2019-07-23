#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>

#ifdef __gnu_linux__
    #include <unistd.h> // Include so we can use getentropy()
#else
    #error "Currently operations.cc only implemented for Gnu/Linux"
#endif

namespace ssc
{
    void generate_random_bytes(u8_t * const buffer, std::size_t num_bytes)
    {
        using namespace std;

        static constexpr auto const & Fail_String = "Failed to getentropy()"
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
            exit   ( EXIT_FAILURE );
        }
    }
    void zero_sensitive(void *buffer, std::size_t num_bytes)
    {
        using namespace std;

        explicit_bzero( buffer, num_bytes );
    }
}
