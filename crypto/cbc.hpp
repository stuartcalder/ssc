#ifndef CBC_HPP
#define CBC_HPP
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <utility>

template< typename block_cipher_t, size_t BLOCK_SIZE >
class CBC
{
public:
  /* COMPILE TIME CHECKS */
  static_assert( (BLOCK_SIZE >= 128), "Modern block ciphers have at least 128-bit blocks!" );
  static_assert( (BLOCK_SIZE % 8 == 0 ), "Block size must be a multiple of 8! A 'byte' must be 8 bits here." );
  /* COMPILE TIME CONSTANTS */
  static constexpr size_t BLOCK_BYTES = (BLOCK_SIZE / 8);
  static constexpr bool micro_optimizations = true;
  /* PUBLIC INTERFACE */
  CBC() = delete;                           // disallow argument-less construction for now
  CBC(block_cipher_t &&blk_c); // 
  ~CBC();
  size_t encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
  size_t decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
private:
  /* PRIVATE STATE */
  block_cipher_t  blk_cipher;
  uint8_t state[ BLOCK_BYTES ] = { 0 };
  /* PRIVATE INTERFACE */
  size_t apply_iso_iec_7816_padding(uint8_t *bytes, const size_t prepadding_size);
  size_t count_iso_iec_7816_padding_bytes( uint8_t *bytes, const size_t padded_size );
  void xor_block(uint8_t *block, const uint8_t *add);
  bool state_is_seeded();
};

// CONSTRUCTORS
template< typename block_cipher_t, size_t BLOCK_SIZE >
CBC<block_cipher_t,BLOCK_SIZE>::CBC( block_cipher_t&& blk_c ) 
  : blk_cipher{ blk_c }
{
}
// DESTRUCTORS
template< typename block_cipher_t, size_t BLOCK_SIZE >
CBC<block_cipher_t,BLOCK_SIZE>::~CBC()
{
  explicit_bzero( state, sizeof(state) );
}
//
template< typename block_cipher_t, size_t BLOCK_SIZE >
size_t CBC<block_cipher_t,BLOCK_SIZE>::apply_iso_iec_7816_padding( uint8_t *bytes, const size_t prepadding_size )
{
  /* Here, bytes_to_add is pre-emptively decremented by 1, as padding
   * at least one byte is necessary for this padding scheme. */
  const size_t bytes_to_add = ( BLOCK_BYTES - (prepadding_size % BLOCK_BYTES) - 1 );
  bytes[ prepadding_size ] = 0x80u; // The byte 0x80 precedes any null bytes (if any) that make up the padding.
  std::memset( (bytes + prepadding_size + 1), 0x00u, bytes_to_add );
  return prepadding_size + 1 + bytes_to_add;
}
template< typename block_cipher_t, size_t BLOCK_SIZE >
size_t CBC<block_cipher_t,BLOCK_SIZE>::count_iso_iec_7816_padding_bytes( uint8_t *bytes, const size_t padded_size )
{
  int i = padded_size - 1;
  while( i > 0 ) {
    if( bytes[i] == 0x80u ) {
      return padded_size - i;
    }
    --i;
  }
  exit(3);
}
template< typename block_cipher_t, size_t BLOCK_SIZE >
void CBC<block_cipher_t,BLOCK_SIZE>::xor_block( uint8_t *block, const uint8_t *add )
{
  if constexpr( micro_optimizations && BLOCK_SIZE == 128 ) {
    /* 128-bit block case */
    auto first_dword  = reinterpret_cast<uint64_t*>( block );
    auto second_dword = reinterpret_cast<const uint64_t*>( add );

    (*first_dword) ^= (*second_dword);
    (*(first_dword + 1)) ^= (*(second_dword + 1));
  } else {
    /* General block case */
    for( size_t i = 0; i < BLOCK_BYTES; ++i )
      block[i] ^= add[i];
  }
}
/*
  bool CBC<block_cipher_t,BLOCK_SIZE>::state_is_seeded()
  * The motive behind this: we zero the state when we're no longer going to use it.
  * if the state is all zeroes, the state is NOT seeded!
*/
template< typename block_cipher_t, size_t BLOCK_SIZE >
bool CBC<block_cipher_t,BLOCK_SIZE>::state_is_seeded()
{
  if constexpr( micro_optimizations && BLOCK_SIZE == 128 ) {
  /* 128-bit block case */
    auto dword_ptr = reinterpret_cast<uint64_t*>( state  );
    return static_cast<bool>( (*(dword_ptr)) | (*(dword_ptr + 1)) );
  } else {
  /* General block case */
    uint8_t ch = 0x00u;
    for( size_t i = 0; i < BLOCK_BYTES; ++i )
      ch |= state[i];
    return static_cast<bool>( ch );
  }
}

template< typename block_cipher_t, size_t BLOCK_SIZE >
size_t CBC<block_cipher_t,BLOCK_SIZE>::encrypt( const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv )
{
  if( iv != nullptr )
    std::memcpy( state, iv, sizeof(state) );
  if( bytes_in != bytes_out ) {
    std::memcpy( bytes_out, bytes_in, size_in );
  }
  const size_t padded_size = apply_iso_iec_7816_padding( bytes_out, size_in );
  const size_t last_block_offset = padded_size - BLOCK_BYTES;
  for( size_t block_offset = 0; block_offset <= last_block_offset; block_offset += BLOCK_BYTES ) {
    uint8_t *current_block = bytes_out + block_offset;
    xor_block( current_block, state );
    blk_cipher.cipher( current_block, current_block );
    std::memcpy( state, current_block, sizeof(state) );
  }
  return padded_size;
}
template< typename block_cipher_t, size_t BLOCK_SIZE >
size_t CBC<block_cipher_t,BLOCK_SIZE>::decrypt( const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv )
{
  if( iv != nullptr )                       // seed the state if possible
    std::memcpy( state, iv, sizeof(state) );
  const size_t last_block_offset = size_in - BLOCK_BYTES;
  uint8_t ciphertext[ BLOCK_BYTES ];
  uint8_t buffer    [ BLOCK_BYTES ];
  for( size_t block_offset = 0; block_offset <= last_block_offset; block_offset += BLOCK_BYTES ) {
    std::memcpy( ciphertext, bytes_in + block_offset, BLOCK_BYTES );
    blk_cipher.inverse_cipher( ciphertext, buffer );
    xor_block( buffer, state );
    std::memcpy( bytes_out + block_offset, buffer, sizeof(buffer) );
    std::memcpy( state, ciphertext, sizeof(state) );
  }
  explicit_bzero( buffer, sizeof(buffer) );
  explicit_bzero( ciphertext, sizeof(ciphertext) );
  return size_in - count_iso_iec_7816_padding_bytes( bytes_out, size_in );
#if 0
  for( size_t block_offset = 0; block_offset <= last_block_offset; block_offset += BLOCK_BYTES ) {
    const uint8_t *ciphertext = bytes_in + block_offset;
    uint8_t *plaintext  = bytes_out + block_offset;
    std::memcpy( buffer, ciphertext, sizeof(buffer) ); // copy ciphertext into buffer
    blk_cipher.inverse_cipher( buffer, buffer );                    // inverse the cipher on the buffer
    xor_block( buffer, state );                                     // xor the buffer with the state (either the IV or the previous ciphertext block) to get the plaintext
    std::memcpy( plaintext, buffer, sizeof(buffer) );// copy the plaintext out
    std::memcpy( state, ciphertext, sizeof(state) );   // copy the ciphertext block into the buffer
  }
  explicit_bzero( buffer, sizeof(buffer) );
  return size_in - count_iso_iec_7816_padding_bytes( bytes_out, size_in );    // return the number of real bytes of the output, to ignore the padding
#endif
}
#endif
