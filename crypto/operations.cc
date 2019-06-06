#include <ssc/crypto/operations.hh>

namespace ssc
{
    void generate_random_bytes(uint8_t * const buffer, size_t num_bytes)
    {
        using namespace std;
        size_t offset = 0;
        while( num_bytes >= 256 ) {
            if( getentropy( (buffer + offset), 256 ) != 0 ) {
                fprintf( stderr, "Failed to getentropy()\n" );
                exit   ( EXIT_FAILURE );
            }
            num_bytes -= 256;
            offset    += 256;
        }
        if( getentropy( (buffer + offset), num_bytes ) != 0 ) {
            fprintf( stderr, "Failed to getentropy()\n" );
            exit   ( EXIT_FAILURE );
        }
    }
    void zero_sensitive(void *buffer, size_t num_bytes)
    {
        using namespace std;
        explicit_bzero( buffer, num_bytes );
    }
}
