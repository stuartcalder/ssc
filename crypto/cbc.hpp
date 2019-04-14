#ifndef CBC_HPP
#define CBC_HPP
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <utility>

/*
 * CBC < block_cipher_t, BLOCK_BITS >
 *
 * This class implements The Cipher-Block-Chaining mode of operation for cryptographic block ciphers.
    * block_cipher_t  =====> Some type that implements four specific methods:
        size_t encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  If IV is nullptr, the "state" is assumed to be already seeded with past invocations
                  If IV is not nullptr, it is used to seed the state for encryption
        size_t decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  If IV is nullptr, the "state" is assumed to be already seeded with past invocations
                  If IV is not nullptr, it is used to seed the state for encryption
        void   encrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  Same IV conditions as above ; does not do any sort of padding ; must only be used with buffers
                  perfectly divisible by BLOCK_BITS
        inline void   decrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  Same conditions as above.
    * BLOCK_BITS      =====> a size_t unsigned integer describing the number of bits in 1 block of the block cipher.
  */
template< typename block_cipher_t, size_t BLOCK_BITS >
class CBC
{
public:
  /* COMPILE TIME CHECKS */
  static_assert( (BLOCK_BITS >= 128), "Modern block ciphers have at least 128-bit blocks!" );
  static_assert( (BLOCK_BITS % 8 == 0 ), "Block size must be a multiple of 8! A 'byte' must be 8 bits here." );
  /* COMPILE TIME CONSTANTS */
  static constexpr size_t BLOCK_BYTES = (BLOCK_BITS / 8);
  static constexpr bool Micro_Optimizations = true;
  /* PUBLIC INTERFACE */
  CBC() = delete;                           // disallow argument-less construction for now
  CBC(block_cipher_t &&blk_c); // 
  ~CBC();
  void   manually_set_state(const uint8_t * const state_bytes);
  void   encrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
  void   decrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
  size_t decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
  size_t encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
private:
  /* PRIVATE STATE */
  block_cipher_t  blk_cipher;
  uint8_t state[ BLOCK_BYTES ] = { 0 };
  /* PRIVATE INTERFACE */
  size_t apply_iso_iec_7816_padding(uint8_t *bytes, const size_t prepadding_size) const;
  size_t count_iso_iec_7816_padding_bytes( const uint8_t * const bytes, const size_t padded_size ) const;
  void xor_block(uint8_t *block, const uint8_t *add) const;
  bool state_is_seeded() const;
};

// CONSTRUCTORS
template< typename block_cipher_t, size_t BLOCK_BITS >
CBC<block_cipher_t,BLOCK_BITS>::CBC(block_cipher_t&& blk_c) 
  : blk_cipher{ blk_c }
{
}
// DESTRUCTORS
template< typename block_cipher_t, size_t BLOCK_BITS >
CBC<block_cipher_t,BLOCK_BITS>::~CBC()
{
  explicit_bzero( state, sizeof(state) );
}
template< typename block_cipher_t, size_t BLOCK_BITS >
void CBC<block_cipher_t,BLOCK_BITS>::manually_set_state(const uint8_t * const state_bytes)
{
  std::memcpy( state, state_bytes, sizeof(state) );
}
template< typename block_cipher_t, size_t BLOCK_BITS >
size_t CBC<block_cipher_t,BLOCK_BITS>::apply_iso_iec_7816_padding(uint8_t *bytes, const size_t prepadding_size) const
{
  /* Here, bytes_to_add is pre-emptively decremented by 1, as padding
   * at least one byte is necessary for this padding scheme. */
  const size_t bytes_to_add = ( BLOCK_BYTES - (prepadding_size % BLOCK_BYTES) - 1 );
  bytes[ prepadding_size ] = 0x80u; // The byte 0x80 precedes any null bytes (if any) that make up the padding.
  std::memset( (bytes + prepadding_size + 1), 0x00u, bytes_to_add );
  return prepadding_size + 1 + bytes_to_add;
}
template< typename block_cipher_t, size_t BLOCK_BITS >
size_t CBC<block_cipher_t,BLOCK_BITS>::count_iso_iec_7816_padding_bytes(const uint8_t * const bytes, const size_t padded_size) const
{
  size_t count = 0;
  for( size_t i = padded_size - 1; padded_size > 0; --i ) {
    ++count;
    if( bytes[i] == 0x80 )
      return count;
  }
  exit(3);
}
template< typename block_cipher_t, size_t BLOCK_BITS >
void CBC<block_cipher_t,BLOCK_BITS>::xor_block(uint8_t *block, const uint8_t *add) const
{
  if constexpr( Micro_Optimizations && BLOCK_BITS == 128 ) {
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
  bool CBC<block_cipher_t,BLOCK_BITS>::state_is_seeded()
  * The motive behind this: we zero the state when we're no longer going to use it.
  * if the state is all zeroes, the state is NOT seeded!
*/
template< typename block_cipher_t, size_t BLOCK_BITS >
bool CBC<block_cipher_t,BLOCK_BITS>::state_is_seeded() const
{
  if constexpr( Micro_Optimizations && BLOCK_BITS == 128 ) {
  /* 128-bit block case */
    auto dword_ptr = reinterpret_cast<const uint64_t*>( state  );
    return static_cast<bool>( (*(dword_ptr)) | (*(dword_ptr + 1)) );
  } else {
  /* General block case */
    uint8_t ch = 0x00u;
    for( int i = 0; i < BLOCK_BYTES; ++i )
      ch |= state[i];
    return static_cast<bool>( ch );
  }
}

template< typename block_cipher_t, size_t BLOCK_BITS >
void CBC<block_cipher_t,BLOCK_BITS>::encrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
{
  using std::memcpy;

  if( iv != nullptr )
    memcpy( state, iv, sizeof(state) );
  if( bytes_in != bytes_out )
    memcpy( bytes_out, bytes_in, size_in );
  const size_t last_block_offset = size_in - BLOCK_BYTES;
  for( size_t b_off = 0; b_off <= last_block_offset; b_off += BLOCK_BYTES ) {
    uint8_t *current_block = bytes_out + b_off;
    xor_block( current_block, state );
    blk_cipher.cipher( current_block, current_block );
    memcpy( state, current_block, sizeof(state) );
  }
}

template< typename block_cipher_t, size_t BLOCK_BITS >
size_t CBC<block_cipher_t,BLOCK_BITS>::encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
{
  using std::memcpy;

  if( iv != nullptr )
    memcpy( state, iv, sizeof(state) );
  if( bytes_in != bytes_out )
    memcpy( bytes_out, bytes_in, size_in );
  const size_t padded_size = apply_iso_iec_7816_padding( bytes_out, size_in );
  const size_t last_block_offset = padded_size - BLOCK_BYTES;
  for( size_t block_offset = 0; block_offset <= last_block_offset; block_offset += BLOCK_BYTES ) {
    uint8_t *current_block = bytes_out + block_offset;
    xor_block( current_block, state );
    blk_cipher.cipher( current_block, current_block );
    memcpy( state, current_block, sizeof(state) );
  }
  return padded_size;
}
template< typename block_cipher_t, size_t BLOCK_BITS >
size_t CBC<block_cipher_t,BLOCK_BITS>::decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
{
  using std::memcpy;

  if( iv != nullptr )
    memcpy( state, iv, sizeof(state) );
  const size_t last_block_offset = (size_in >= BLOCK_BYTES) ? (size_in - BLOCK_BYTES) : 0;
  uint8_t ciphertext[ BLOCK_BYTES ];
  uint8_t buffer    [ BLOCK_BYTES ];
  for( size_t b_off = 0; b_off <= last_block_offset; b_off += BLOCK_BYTES ) {
    const uint8_t *block_in  = bytes_in  + b_off;
    uint8_t       *block_out = bytes_out + b_off;
    memcpy( ciphertext, block_in, sizeof(ciphertext) );
    blk_cipher.inverse_cipher( ciphertext, buffer );
    xor_block( buffer, state );
    memcpy( block_out, buffer, sizeof(buffer) );
    memcpy( state, ciphertext, sizeof(state) );
  }
  explicit_bzero( buffer, sizeof(buffer) );
  explicit_bzero( ciphertext, sizeof(ciphertext) );
  return size_in - count_iso_iec_7816_padding_bytes( bytes_out, size_in );
}
template< typename block_cipher_t, size_t BLOCK_BITS >
void CBC<block_cipher_t,BLOCK_BITS>::decrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
{
  using std::memcpy;

  if( iv != nullptr )
    memcpy( state, iv, sizeof(state) );
  const size_t last_block_offset = size_in - BLOCK_BYTES;
  uint8_t ciphertext[ BLOCK_BYTES ];
  uint8_t buffer    [ BLOCK_BYTES ];
  for( size_t b_off = 0; b_off <= last_block_offset; b_off += BLOCK_BYTES ) {
    const uint8_t *block_in  = bytes_in  + b_off;
    uint8_t       *block_out = bytes_out + b_off;
    memcpy( ciphertext, block_in, sizeof(ciphertext) );
    blk_cipher.inverse_cipher( ciphertext, buffer );
    xor_block( buffer, state );
    memcpy( block_out, buffer, sizeof(buffer) );
    memcpy( state, ciphertext, sizeof(state) );
  }
  explicit_bzero( buffer, sizeof(buffer) );
  explicit_bzero( ciphertext, sizeof(ciphertext) );
}
#endif
