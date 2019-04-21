#pragma once
#include "threefish_runtime_keyschedule.hpp"
#include "operations.hpp"

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
class UBI
{
public:
/* Compile-Time checks, Constants, and Aliases */
  static_assert( State_Bits % 8 == 0, "Must be divisible into 8-bit bytes" );
  static_assert( State_Bytes % 8 == 0, "Must be divisible into 8 64-bit words" );
  static constexpr const size_t State_Bytes = State_Bits / 8;
  static constexpr const size_t Tweak_Bits  = 128;
  static constexpr const size_t Tweak_Bytes = Tweak_Bits / 8;
  using TBC_t = Tweakable_Block_Cipher_t;
/* Constructor(s) */
/* Public Interface */
  void chain(const uint64_t * const in,
             const uint64_t * const message,
             uint64_t       * const out,
             const size_t           message_size,
             const uint8_t          type);
private:
/* Private Compile-Time constants */
  static constexpr const auto & _xor_block = xor_block< State_Bits >;
/* Private Data */
  uint64_t _tweak_state[ Tweak_Bytes / sizeof(uint64_t) ] = { 0 };
  uint64_t _key_state  [ State_Bytes / sizeof(uint64_t) ];
  uint64_t _msg_state  [ State_Bytes / sizeof(uint64_t) ];
/* Private Interface */
  void _set_tweak_state(const uint64_t * const length,
                        const uint8_t          first_or_last_mask = 0);
};

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::chain
  (const uint64_t * const in,
   const uint64_t * const message,
   uint64_t       * const out,
   const size_t     message_size,
   const uint8_t    type)
{
/* Ensure none of the input pointers are nullptr */
  if( in == nullptr || message == nullptr || out == nullptr ) {
    exit( EXIT_FAILURE );
  }
  //TODO
}

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Bits >
void UBI<Tweakable_Block_Cipher_t,State_Bits>::_set_tweak_state
  (const uint64_t * const length,
   const uint8_t    first_or_last_mask)
{
  uint8_t * const first_8_bits_out = reinterpret_cast<uint8_t*>( _tweak_state );
  (*first_8_bits_out) &= 0b0011'1111;
  (*first_8_bits_out) |= first_or_last_mask;
#if 0
  // Set position field
  const auto &     first_64_pos_bits_in  = length;
  uint32_t * const  last_32_pos_bits_in  = reinterpret_cast<uint32_t*>( length + 1 );
  const auto &     first_64_pos_bits_out = _tweak_state;
  uint32_t * const  last_32_pos_bits_out = reinterpret_cast<uint32_t*>( _tweak_state + 1 );
  (*first_64_pos_bits_out) = (*first_64_pos_bits_in);
  (*last_32_pos_bits_out)  = (*last_32_pos_bits_in);
  // Set first / last field
  { // +
    uint8_t * const last_8_fol_bits_out = (reinterpret_cast<uint8_t*>( _tweak_state ) + sizeof(_tweak_state) - 1);
    (*last_8_fol_bits_out) &= 0b0011'1111;
    (*last_8_fol_bits_out) |= first_or_last_mask; // first mask = 0b00000010
  } // -
#endif
}




