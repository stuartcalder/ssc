#include <ssc/crypto/sspkdf.hh>

void SSPKDF (uint8_t * const derived_key,
             const uint8_t * const password,
             const int password_length,
             const uint8_t * const salt,
             const int number_iterations,
             const int number_concatenations)
{
    using std::memcpy;
    constexpr const int    State_Bits = 512;
    constexpr const int    State_Bytes = State_Bits / 8;
    constexpr const int    Salt_Bits = 128;
    constexpr const int    Salt_Bytes = Salt_Bits / 8;
    Skein<State_Bits> skein;
    using Index_t = uint32_t;
    const uint64_t concat_size = (static_cast<uint64_t>(password_length) + Salt_Bytes + sizeof(Index_t)) * number_concatenations;
    auto concat_buffer = std::make_unique<uint8_t[]>( concat_size );
  
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
        uint8_t key   [ State_Bytes ];
        uint8_t buffer[ State_Bytes ];
        skein.hash( key, concat_buffer.get(), concat_size, sizeof(key) );
        skein.MAC ( buffer, concat_buffer.get(), key, concat_size, sizeof(key), sizeof(buffer) );
        xor_block<512>( key, buffer );
        for ( int i = 1; i < number_iterations; ++i ) {
            skein.MAC( buffer, buffer, key, sizeof(buffer), sizeof(key), sizeof(buffer) );
            xor_block<512>( key, buffer );
        }
        skein.hash( derived_key, buffer, sizeof(buffer), sizeof(buffer) );
        zero_sensitive( key   , sizeof(key) );
        zero_sensitive( buffer, sizeof(buffer) );
    }
    zero_sensitive( concat_buffer.get(), concat_size );
}
