#pragma once
#include <cstdio>
#include <cstdlib>
#include "operations.hh"

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
class UBI
{
public:
/* Compile-Time checks, Constants, and Aliases */
  static_assert( State_Bits % 8 == 0, "Must be divisible into 8-bit bytes" );
  static constexpr const size_t State_Bytes = State_Bits / 8;
  static_assert( State_Bytes % 8 == 0, "Must be divisible into 64-bit words" );
  static constexpr const size_t Tweak_Bits  = 128;
  static constexpr const size_t Tweak_Bytes = Tweak_Bits / 8;
  enum class Type_Mask_t : uint8_t {
    T_key = 0,
    T_cfg = 4,
    T_prs = 8,
    T_pk  = 12,
    T_kdf = 16,
    T_non = 20,
    T_msg = 48,
    T_out = 63
  };
/* Constructor(s) */
/* Public Interface */
  void chain(const Type_Mask_t      type_mask,
             const uint8_t * const       message,
             const uint64_t      message_size,
             const uint8_t * const in = nullptr);

  uint8_t * get_key_state();
  void clear_key_state();
private:
/* Private Compile-Time constants */
  static constexpr const auto & _xor_block = xor_block< State_Bits >;
/* Private Data */
  Tweakable_Block_Cipher_t _block_cipher;
#if 1
  uint8_t  _tweak_state[ Tweak_Bytes ];
  uint8_t  _key_state  [ State_Bytes ];
  uint8_t  _msg_state  [ State_Bytes ];
#endif
#if 0
  uint64_t _tweak_state[ Tweak_Bytes / sizeof(uint64_t) ];
  uint64_t _key_state  [ State_Bytes / sizeof(uint64_t) ];
  uint64_t _msg_state  [ State_Bytes / sizeof(uint64_t) ];
#endif
/* Private Interface */
  void       _set_tweak_first();
  void       _set_tweak_last();
  void       _clear_tweak_first();
  void       _clear_tweak_last();
  void       _clear_tweak_all();
  void       _set_tweak_type(const Type_Mask_t t_mask);
  void       _clear_msg();
  uint64_t   _read_msg_block(const uint8_t * const message_offset,
                             const uint64_t        bytes_left);
};

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::chain
  (const Type_Mask_t type_mask,
   const uint8_t  * const message,
   const uint64_t message_size,
   const uint8_t  * const in)
{///////////////////BEGIN CHAINING////////////////////////////////////
  auto message_offset = reinterpret_cast<const uint8_t *>(message);
/* Ensure none of the input pointers are nullptr */
  if( message == nullptr ) {
    std::fprintf( stderr, "Nullptr for message in UBI call.\n" );
    std::exit( EXIT_FAILURE );
  }
/* Setup Tweak */
  _clear_tweak_all();
  _set_tweak_type( type_mask );
  _set_tweak_first();
/* Setup initial key and message state */
  if( in != nullptr ) {
    std::memcpy( _key_state, in, sizeof(_key_state) );
  }
/* Get message */
  uint64_t message_bytes_left = message_size;
  uint64_t bytes_just_read    = _read_msg_block( message_offset, message_bytes_left );
  message_offset     += bytes_just_read;
  message_bytes_left -= bytes_just_read;
  if( message_bytes_left == 0 ) {
    _set_tweak_last();
  }
/* Set the position, and get a pointer to it for use later */
  uint64_t * const position = reinterpret_cast<uint64_t *>(_tweak_state);
  (*position) = bytes_just_read;
  // First block Setup
  _block_cipher.rekey( _key_state, _tweak_state );
  // First block
  _block_cipher.cipher( _msg_state, _key_state );
  _xor_block( _key_state, _msg_state );
  _clear_tweak_first();

  // Intermediate blocks (assuming first block wasn't also the last block)
  while( message_bytes_left > State_Bytes ) {
    bytes_just_read = _read_msg_block( message_offset, message_bytes_left );
    message_offset     += bytes_just_read;
    message_bytes_left -= bytes_just_read;
    (*position)        += bytes_just_read;
    _block_cipher.rekey( _key_state, _tweak_state );
    _block_cipher.cipher( _msg_state, _key_state );
    _xor_block( _key_state, _msg_state );
  }

  // Last block (assuming first block wasn't also the last block)
  if( message_bytes_left > 0 ) {
    _set_tweak_last();
    (*position) += _read_msg_block( message_offset, message_bytes_left );
    _block_cipher.rekey( _key_state, _tweak_state );
    _block_cipher.cipher( _msg_state, _key_state );
    _xor_block( _key_state, _msg_state );
  }
  
}//////////////////END CHAINING//////////////////////////////////////

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_set_tweak_first
  ()
{
  _tweak_state[ sizeof(_tweak_state) - 1 ] |= 0b0100'0000;
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_set_tweak_last
  ()
{
  _tweak_state[ sizeof(_tweak_state) - 1 ] |= 0b1000'0000;
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_clear_tweak_first
  ()
{
  _tweak_state[ sizeof(_tweak_state) - 1 ] &= 0b1011'1111;
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_clear_tweak_last
  ()
{
  _tweak_state[ sizeof(_tweak_state) - 1 ] &= 0b0111'1111;
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_clear_tweak_all
  ()
{
  std::memset( _tweak_state, 0, sizeof(_tweak_state) );
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_set_tweak_type
  (const Type_Mask_t type_mask)
{
  _tweak_state[ sizeof(_tweak_state) - 1 ] |= static_cast<uint8_t>(type_mask);
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_clear_msg
  ()
{
  std::memset( _msg_state, 0, sizeof(_msg_state) );
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
uint64_t UBI<Tweakable_Block_Cipher_t,State_Bits>::_read_msg_block
  (const uint8_t * const message_offset,
   const uint64_t         bytes_left)
{
  uint64_t bytes_read;
  if( bytes_left >= State_Bytes ) {
    std::memcpy( _msg_state, message_offset, State_Bytes );
    bytes_read = State_Bytes;
  }
  else {
    _clear_msg();
    std::memcpy( _msg_state, message_offset, bytes_left );
    bytes_read = bytes_left;
  }
  return bytes_read;
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
uint8_t * UBI<Tweakable_Block_Cipher_t,State_Bits>::get_key_state
  ()
{
  return _key_state;
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::clear_key_state
  ()
{
  std::memset( _key_state, 0, sizeof(_key_state) );
}
