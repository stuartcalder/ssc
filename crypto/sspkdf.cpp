#include "sspkdf.hpp"

void SSPKDF(uint8_t * const derived_key,
            const uint8_t * const password,
            const int password_length,
            const uint8_t * const salt,
            const int number_iterations,
            const int number_concatenations)
{
  constexpr const int Salt_Bits = 128;
  constexpr const int Salt_Bytes = Salt_Bits / 8;
  Skein<512> skein;
  uint32_t index = 0;
  const uint64_t concat_size = (static_cast<uint64_t>(password_length) + Salt_Bytes + sizeof(index)) * number_concatenations;
  auto concat_buffer = std::make_unique<uint8_t[]>( concat_size );
  
  { //  +
    auto buf_ptr = concat_buffer.get();
    auto buf_end = buf_ptr + concat_size;
    while( buf_ptr < buf_end ) {
      std::memcpy( buf_ptr, password, password_length );
      buf_ptr += password_length;
      std::memcpy( buf_ptr, salt, Salt_Bytes );
      buf_ptr += Salt_Bytes;
      std::memcpy( buf_ptr, &index, sizeof(index) );
      buf_ptr += sizeof(index);
      ++index;
    }
  } //  -
  { //  +
    uint8_t key   [ 64 ];
    uint8_t buffer[ 64 ];
    skein.hash( key, concat_buffer.get(), concat_size, sizeof(key) );
    skein.MAC ( buffer, concat_buffer.get(), key, concat_size, sizeof(key), sizeof(buffer) );
    xor_block<512>( key, buffer );
    for( int i = 1; i < number_iterations; ++i ) {
      skein.MAC( buffer, buffer, key, sizeof(buffer), sizeof(key), sizeof(buffer) );
      xor_block<512>( key, buffer );
    }
    skein.hash( derived_key, buffer, sizeof(buffer), sizeof(buffer) );
    explicit_bzero( key   , sizeof(key) );
    explicit_bzero( buffer, sizeof(buffer) );
  } //  -
  explicit_bzero( concat_buffer.get(), concat_size );
}
