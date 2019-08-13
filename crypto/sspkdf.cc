#include <ssc/crypto/sspkdf.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>

namespace ssc
{
    void SSPKDF(u8_t * const __restrict derived_key,
                char const * __restrict password,
                int const               password_length,
                u8_t const * __restrict salt,
                u32_t const             number_iterations,
                u32_t const             number_concatenations)
    {
        using std::memcpy;
        constexpr const int    State_Bits = 512;
        constexpr const int    State_Bytes = State_Bits / 8;
        constexpr const int    Salt_Bits = 128;
        constexpr const int    Salt_Bytes = Salt_Bits / 8;
        Skein<State_Bits> skein;
        using Index_t = u32_t;
        const u64_t concat_size = (static_cast<u64_t>(password_length) + Salt_Bytes + sizeof(Index_t)) * number_concatenations;
        auto concat_buffer = std::make_unique<u8_t[]>( concat_size );
        
        {
            Index_t index = 0;
            auto buf_ptr = concat_buffer.get();
            const auto buf_end = buf_ptr + concat_size;
            while ( buf_ptr < buf_end ) {
                memcpy( buf_ptr, password, password_length );
                buf_ptr += password_length;
                memcpy( buf_ptr, salt, Salt_Bytes );
                buf_ptr += Salt_Bytes;
                memcpy( buf_ptr, &index, sizeof(index) );
                buf_ptr += sizeof(index);
                ++index;
            }
        }
        {
            u8_t key    [State_Bytes];
            u8_t buffer [State_Bytes];
            skein.hash( key, concat_buffer.get(), concat_size, sizeof(key) );
            skein.MAC ( buffer, concat_buffer.get(), key, concat_size, sizeof(key), sizeof(buffer) );
            xor_block<State_Bits>( key, buffer );
            for ( u32_t i = 1; i < number_iterations; ++i ) {
                skein.MAC( buffer, buffer, key, sizeof(buffer), sizeof(key), sizeof(buffer) );
                xor_block<State_Bits>( key, buffer );
            }
            skein.hash( derived_key, buffer, sizeof(buffer), State_Bytes );
            zero_sensitive( key   , sizeof(key) );
            zero_sensitive( buffer, sizeof(buffer) );
        }
        zero_sensitive( concat_buffer.get(), concat_size );
    }
}
