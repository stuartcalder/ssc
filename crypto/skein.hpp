#pragma once
#include "threefish.hpp"
#include "ubi.hpp"

template< size_t State_Bits >
class Skein
{
public:
  using UBI_t = UBI< Threefish<State_Bits>, State_Bits >;
  using Type_Mask_t = UBI_t::Type_Mask;
  void hash(const void * const in, void * const out, const uint64_t bytes_in) const;
private:
  void _process_config_block (UBI_t & ubi,
                              const uint64_t num_output_bits,
                              const uint64_t * const key_in) const;
  void _process_message_block(UBI_t & ubi,
                              const uint8_t * const message_in,
                              const uint64_t message_size) const;
  void _output_transform     (UBI_t & ubi,
                              void * const out,
                              const uint64_t * key_in,
                              const uint64_t num_output_bytes) const;
                              


                              
};

template< size_t State_Bits >
void Skein<State_Bits>::_process_config_block(UBI_t & ubi,
                                              const uint64_t num_output_bits,
                                              const uint64_t * const key_in) const
{
/* Setup configuration string */
  uint8_t config[ 32 ] = {
    // first 4 bytes
    0x53, 0x48, 0x41, 0x33, // schema identifier "SHA3"
    // next 2 bytes
    0x80, 0x00,             // version number (1)
    // next 2 bytes
    0x00, 0x00,             // reserved (0)
    // next 8 bytes
    0x00, 0x00, 0x00, 0x00, // output length
    0x00, 0x00, 0x00, 0x00,
    // remaining 16 bytes
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };
  *(reinterpret_cast<uint64_t *>( config + 8 )) = output_length;
/* Process it */
  ubi.chain( Type_Mask_t::T_cfg,
             config,
             sizeof(config),
             key_in );
}

template< size_t State_Bits >
void Skein<State_Bits>::_process_message_block(UBI_t & ubi,
                                               const uint8_t * const message_in,
                                               const uint64_t message_size) const
{
  ubi.chain( Type_Mask_t::T_msg, message_in, message_size );
}

template< size_t State_Bits >
void Skein<State_Bits>::_output_transform(UBI_t & ubi,
                                          void * const out,
                                          const uint64_t * key_in,
                                          const uint64_t num_output_bytes) const
{
  uint8_t * bytes_out = out;
  uint64_t number_iterations = num_output_bytes / State_Bytes;
  uint64_t bytes_left = num_output_bytes;
  if( (num_output_bytes % State_Bytes) != 0 ) {
    ++number_iterations;
  }
  for( uint64_t i = 0; i < number_iterations; ++i ) {
    ubi.chain( Type_Mask_t::T_out, i, sizeof(uint64_t), key_in );
    if( bytes_left >= State_Bytes ) {
      std::memcpy( bytes_out, ubi.get_key_state(), State_Bytes );
      bytes_out  += State_Bytes;
      bytes_left -= State_Bytes;
    }
    else {
      std::memcpy( bytes_out, ubi.get_key_state(), bytes_left );
      break;
    }
  }
}

template< size_t State_Bits >
void Skein<State_Bits>::hash(const void * const in, void * const out, const uint64_t bytes_in) const
{
  UBI_t ubi;
  { // +
    uint8_t key_in[ State_Bytes ] = { 0 };
    _process_config_block ( ubi, State_Bits, key_in );
  } // -
  _process_message_block( ubi, in, bytes_in );
  uint64_t key[ State_Bytes / sizeof(uint64_t) ];
  std::memcpy( key, ubi.get_key_state(), sizeof(key) );
  _output_transform( ubi, out, key, State_Bytes );
}
