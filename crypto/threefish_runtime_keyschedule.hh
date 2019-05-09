#ifndef THREEFISH_RUNTIME_KEYSCHEDULE_HPP
#define THREEFISH_RUNTIME_KEYSCHEDULE_HPP
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "operations.hh"

template< size_t KEY_BITS=512 >
class Threefish_Runtime_Keyschedule
{
public:
  /* STATIC CHECKS */
  static constexpr const size_t Key_Bits = KEY_BITS;
  static_assert ( 
      (Key_Bits == 256 || Key_Bits == 512 || Key_Bits == 1024), "Invalid keysize" 
  );
  static_assert (
      (CHAR_BIT == 8), "This implementation needs 8-bit chars"
  );
  /* PUBLIC CONSTANTS */
  static constexpr const int       Number_Words   = Key_Bits / 64;
  static constexpr const int       Number_Rounds  = [](auto words){ if( words == 16 ) return 80; else return 72; }( Number_Words );
  static constexpr const int       Number_Subkeys = (Number_Rounds / 4) + 1;
  static constexpr const uint64_t  Constant_240   = 0x1bd1'1bda'a9fc'1a22;
  /* PUBLIC FUNCTIONS */
  inline void set_key  (const uint64_t *k);  // forward declared
  inline void set_tweak(const uint64_t *tw); // forward declared
  /* CONSTRUCTORS / DESTRUCTORS */
  Threefish_Runtime_Keyschedule() = delete;
  Threefish_Runtime_Keyschedule(const uint64_t *k, const uint64_t *tw = nullptr)
  {
    set_key( k );
    set_tweak( tw );
  }
  ~Threefish_Runtime_Keyschedule(); // forward declared
  /* PUBLIC FUNCTIONS */
  void cipher(const uint64_t *in, uint64_t *out); // forward declared
  void cipher(const uint8_t *in, uint8_t *out)
  {
    cipher( reinterpret_cast<const uint64_t*>(in), reinterpret_cast<uint64_t*>(out) );
  }
  void inverse_cipher(const uint64_t *in, uint64_t *out); // forward declared
  void inverse_cipher(const uint8_t *in, uint8_t *out)
  {
    inverse_cipher( reinterpret_cast<const uint64_t*>(in), reinterpret_cast<uint64_t*>(out) );
  }
private:
  /* PRIVATE DATA */
  uint64_t state         [ Number_Words ];
  uint64_t subkey_buffer [ Number_Words ];
  uint64_t key           [ Number_Words + 1 ];
  uint64_t tweak         [ 3 ];
  /* PRIVATE FUNCTIONS */
  void     MIX                  (uint64_t *x0, uint64_t *x1, const int round, const int index) const;
  void     inverse_MIX          (uint64_t *x0, uint64_t *x1, const int round, const int index) const;
  void     calculate_subkey     (const int subkey_index);
  void     add_subkey           (const int round);
  void     subtract_subkey      (const int round);
  uint64_t get_rotate_constant  (const int round, const int index) const;
  uint64_t permute_index        (const int i) const;
  uint64_t inverse_permute_index(const int i) const;
};

template< size_t KEY_BITS >
Threefish_Runtime_Keyschedule<KEY_BITS>::~Threefish_Runtime_Keyschedule()
{
  explicit_bzero( state        , sizeof(state) );
  explicit_bzero( subkey_buffer, sizeof(subkey_buffer) );
  explicit_bzero( key          , sizeof(key) );
  explicit_bzero( tweak        , sizeof(tweak) );
}

template< size_t KEY_BITS >
void Threefish_Runtime_Keyschedule<KEY_BITS>::set_key(const uint64_t *k)
{
  std::memcpy( key, k, sizeof(uint64_t) * Number_Words );
  uint64_t parity_word = Constant_240;
  for( int i = 0; i < Number_Words; ++i )
    parity_word ^= key[i];
  key[ Number_Words ] = parity_word;
}


template< size_t KEY_BITS >
void Threefish_Runtime_Keyschedule<KEY_BITS>::set_tweak(const uint64_t *tw)
{
  if( tw != nullptr ) {
    std::memcpy( tweak, tw, sizeof(uint64_t) * 2 );
    tweak[2] = tweak[0] ^ tweak[1];
  } else {
    std::memset( tweak, 0, sizeof(tweak) );
  }
}

template< size_t KEY_BITS >
void Threefish_Runtime_Keyschedule<KEY_BITS>::MIX(uint64_t *x0, uint64_t *x1, const int round, const int index) const
{
  auto & y0 = x0;
  auto & y1 = x1;

  (*y0) = ( (*x0) + (*x1) );
  (*y1) = ( rotate_left<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ^ (*y0) );
}

template< size_t KEY_BITS >
void Threefish_Runtime_Keyschedule<KEY_BITS>::inverse_MIX(uint64_t *x0, uint64_t *x1, const int round, const int index) const
{
  auto & y0 = x0;
  auto & y1 = x1;

  (*y1) = ( (*x0) ^ (*x1) );
  (*y1) = rotate_right<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ;
  (*y0) = (*x0) - (*y1);

}

template< size_t KEY_BITS >
uint64_t Threefish_Runtime_Keyschedule<KEY_BITS>::get_rotate_constant(const int round, const int index) const
{
  static_assert (
      Number_Words == 4 || Number_Words == 8 || Number_Words == 16,
      "Invalid Number_Words. 4, 8, 16 only."
  );
  if constexpr( Number_Words == 4 ) {
    static constexpr const uint64_t rc[8][2] = {
      { 14, 16 }, //d = 0
      { 52, 57 }, //d = 1
      { 23, 40 }, //d = 2
      {  5, 37 }, //d = 3
      { 25, 33 }, //d = 4
      { 46, 12 }, //d = 5
      { 58, 22 }, //d = 6
      { 32, 32 }  //d = 7
    };
    return rc[ (round % 8) ][ index ] ;
  } else if constexpr( Number_Words == 8 ) {
    static constexpr const uint64_t rc[8][4] = {
      { 46, 36, 19, 37 },
      { 33, 27, 14, 42 },
      { 17, 49, 36, 39 },
      { 44,  9, 54, 56 },
      { 39, 30, 34, 24 },
      { 13, 50, 10, 17 },
      { 25, 29, 39, 43 },
      {  8, 35, 56, 22 }
    };
    return rc[ (round % 8) ][ index ];
  } else if constexpr( Number_Words == 16 ) {
    static constexpr const uint64_t rc[8][8] = {
      { 24, 13,  8, 47,  8, 17, 22, 37 },
      { 38, 19, 10, 55, 49, 18, 23, 52 },
      { 33,  4, 51, 13, 34, 41, 59, 17 },
      {  5, 20, 48, 41, 47, 28, 16, 25 },
      { 41,  9, 37, 31, 12, 47, 44, 30 },
      { 16, 34, 56, 51,  4, 53, 42, 41 },
      { 31, 44, 47, 46, 19, 42, 44, 25 },
      {  9, 48, 35, 52, 23, 31, 37, 20 }
    };
    return rc[ (round % 8) ][ index ];
  }
}

template <size_t KEY_BITS>
void Threefish_Runtime_Keyschedule<KEY_BITS>::calculate_subkey(const int subkey_index)
{
  for( int i = 0; i <= (Number_Words - 4); ++i ) {
    subkey_buffer[i] = key[ (subkey_index + i) % (Number_Words + 1) ];
  }
  subkey_buffer[ Number_Words - 3 ] =
      key[ (subkey_index + (Number_Words - 3)) % (Number_Words + 1) ] + tweak[ subkey_index % 3 ];
  subkey_buffer[ Number_Words - 2 ] =
      key[ (subkey_index + (Number_Words - 2)) % (Number_Words + 1) ] + tweak[ (subkey_index + 1) % 3 ];
  subkey_buffer[ Number_Words - 1 ] =
      key[ (subkey_index + (Number_Words - 1)) % (Number_Words + 1) ] + static_cast<uint64_t>(subkey_index);
}

template <size_t KEY_BITS>
void Threefish_Runtime_Keyschedule<KEY_BITS>::add_subkey(const int round)
{
  const int subkey_index = round / 4;
  calculate_subkey( subkey_index );
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] += subkey_buffer[i];
  }
}

template <size_t KEY_BITS>
void Threefish_Runtime_Keyschedule<KEY_BITS>::subtract_subkey(const int round)
{
  const int subkey_index = round / 4;
  calculate_subkey( subkey_index );
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] -= subkey_buffer[i];
  }
}

template <size_t KEY_BITS>
void Threefish_Runtime_Keyschedule<KEY_BITS>::cipher(const uint64_t *in, uint64_t *out)
{
  std::memcpy( state, in, sizeof(state) );
  for( int round = 0; round < Number_Rounds; ++round ) {
    // Adding subkeys
    if( round % 4 == 0 )
      add_subkey( round );
    // MIXing
    for( int j = 0; j <= (Number_Words / 2) - 1; ++j )
      MIX( (state + (2 * j)), (state + (2 * j) + 1), round, j );
    // Permutations
    {//+
      uint64_t state_copy[ sizeof(state) ];
      std::memcpy( state_copy, state, sizeof(state_copy) );
      for( int i = 0; i < Number_Words; ++i )
        state[i] = state_copy[ permute_index( i ) ];
      explicit_bzero( state_copy, sizeof(state_copy) );
    }//-
  }
  add_subkey( Number_Rounds );
  std::memcpy( out, state, sizeof(state) );
}

template <size_t KEYSIZE>
void Threefish_Runtime_Keyschedule<KEYSIZE>::inverse_cipher(const uint64_t *in, uint64_t *out)
{
  std::memcpy( state, in, sizeof(state) );
  subtract_subkey( Number_Rounds );
  for( int round = Number_Rounds - 1; round >= 0; --round ) {
    {//+
      uint64_t state_copy[ Number_Words ];
      std::memcpy( state_copy, state, sizeof(state_copy) );
      for( int i = 0; i < Number_Words; ++i )
        state[i] = state_copy[ inverse_permute_index( i ) ];
      explicit_bzero( state_copy, sizeof(state_copy) );
    }//-
    for( int j = 0; j<= (Number_Words / 2) -1; ++j )
      inverse_MIX( (state + (2 * j)), (state + (2 * j) + 1), round, j );
    if( round % 4 == 0 )
      subtract_subkey( round );
  }
  std::memcpy( out, state, sizeof(state) );
}

template <size_t KEY_BITS>
uint64_t Threefish_Runtime_Keyschedule<KEY_BITS>::permute_index(const int i) const
{
  if constexpr( Number_Words == 4 ) {
    switch( i ) {
      case 0: return 0;
      case 1: return 3;
      case 2: return 2;
      case 3: return 1;
    }
  } else if constexpr( Number_Words == 8 ) {
    static constexpr const uint64_t perm[] = {
/* i  0  1  2  3  4  5  6  7 */
      2, 1, 4, 7, 6, 5, 0, 3
    };
    return perm[i];
  } else if constexpr( Number_Words == 16 ) {
    static constexpr const uint64_t perm[] = {
/* i  0  1  2   3  4   5  6   7   8  9  10 11  12 13 14 15 */
      0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1
    };
    return perm[i];
  }
}

template <size_t KEY_BITS>
uint64_t Threefish_Runtime_Keyschedule<KEY_BITS>::inverse_permute_index(const int i) const
{
  if constexpr( Number_Words == 4 ) {
    switch( i ) {
      case 0: return 0;
      case 1: return 3;
      case 2: return 2;
      case 3: return 1;
    }
  } else if constexpr( Number_Words == 8 ) {
    static constexpr const uint64_t perm[] = {
/* i  0  1  2  3  4  5  6  7 */
      6, 1, 0, 7, 2, 5, 4, 3
    };
    return perm[i];
  } else if constexpr( Number_Words == 16 ) {
    static constexpr const uint64_t perm[] = {
/* i  0   1  2   3  4   5  6  7   8  9  10 11  12 13  14 15 */
      0, 15, 2, 11, 6, 13, 4, 9, 14, 1,  8, 5, 10, 3, 12, 7
    };
    return perm[i];
  }
}


#endif
