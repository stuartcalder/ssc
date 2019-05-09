#ifndef THREEFISH_PRECOMPUTED_KEYSCHEDULE_HPP
#define THREEFISH_PRECOMPUTED_KEYSCHEDULE_HPP
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "operations.hh"

template< size_t KEY_BITS=512 >
class Threefish_Precomputed_Keyschedule
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
  /* CONSTRUCTORS / DESTRUCTORS */
  Threefish_Precomputed_Keyschedule() = delete;
  Threefish_Precomputed_Keyschedule(const uint64_t *k, const uint64_t *tw = nullptr) {
      expand_key( k, tw );
  }
  ~Threefish_Precomputed_Keyschedule(); // forward declared
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
  void rekey(const uint64_t *new_key, const uint64_t *new_tweak = nullptr)
  {
    expand_key( new_key, new_tweak );
  }
private:
  /* PRIVATE DATA */
  uint64_t state       [ Number_Words ];
  uint64_t key_schedule[ Number_Subkeys * Number_Words ];
  /* PRIVATE FUNCTIONS */
  void     MIX                  (uint64_t *x0, uint64_t *x1, const int round, const int index) const;
  void     inverse_MIX          (uint64_t *x0, uint64_t *x1, const int round, const int index) const;
  void     expand_key           (const uint64_t *key, const uint64_t *tweak);
  void     add_subkey           (const int round);
  void     subtract_subkey      (const int round);
  uint64_t get_rotate_constant  (const int round, const int index) const;
  uint64_t permute_index        (const int i) const;
  uint64_t inverse_permute_index(const int i) const;
};

template< size_t KEY_BITS >
Threefish_Precomputed_Keyschedule<KEY_BITS>::~Threefish_Precomputed_Keyschedule()
{
  explicit_bzero( key_schedule, sizeof(key_schedule) );
  explicit_bzero( state, sizeof(state) );
}

template< size_t KEY_BITS >
void Threefish_Precomputed_Keyschedule<KEY_BITS>::MIX(uint64_t *x0, uint64_t *x1, const int round, const int index) const
{
  uint64_t * const y0 = x0;
  uint64_t * const y1 = x1;

  (*y0) = ((*x0) + (*x1));
  (*y1) = ( rotate_left<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ^ (*y0) );
}

template< size_t KEY_BITS >
void Threefish_Precomputed_Keyschedule<KEY_BITS>::inverse_MIX(uint64_t *y0, uint64_t *y1, const int round, const int index) const
{
  uint64_t * const x0 = y0;
  uint64_t * const x1 = y1;

  (*x1) = ((*y0) ^ (*y1));
  (*x1) = rotate_right<uint64_t>( (*y1), get_rotate_constant( round, index ) ) ;
  (*x0) = (*y0) - (*x1);

}

template< size_t KEY_BITS >
uint64_t Threefish_Precomputed_Keyschedule<KEY_BITS>::get_rotate_constant(const int round, const int index) const
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

template <size_t KEY_BITS >
void Threefish_Precomputed_Keyschedule<KEY_BITS>::expand_key(const uint64_t *k, const uint64_t *tw)
{
  using std::memcpy;
  
  // key / tweak setup
  uint64_t key  [ Number_Words + 1 ]; // Big enough for the parity word
  uint64_t tweak[ 3 ];
  for( int i = 0; i < Number_Words; ++i )
    key[i] = k[i];
  if( tw != nullptr ) { // If a valid tweak was supplied
    tweak[0] = tw[0];
    tweak[1] = tw[1];
    // Tweak parity word
    tweak[2] = tweak[0] ^ tweak[1];
  } else {              // If a valid tweak wasn't supplied
    tweak[0] = 0;
    tweak[1] = 0;
    tweak[2] = 0;
  }

  // Define parity words for the key. (tweak parity word is above)
  key[ Number_Words ] = Constant_240;
  for( int i = 0; i < Number_Words; ++i ) {
    key[ Number_Words ] ^= key[i];
  }

  // Arbitrary keyschedule generation
  for( int subkey = 0; subkey < Number_Subkeys; ++subkey ) {// for each subkey
    const int subkey_index = subkey * Number_Words;
    for( int i = 0; i <= Number_Words - 4; ++i )// each word of the subkey
      key_schedule[ subkey_index + i ] = key[ (subkey + i) % (Number_Words + 1) ];
    key_schedule[ subkey_index + (Number_Words - 3) ] = ( key[ (subkey + (Number_Words - 3)) % (Number_Words + 1) ] + tweak[ subkey % 3 ] );
    key_schedule[ subkey_index + (Number_Words - 2) ] = ( key[ (subkey + (Number_Words - 2)) % (Number_Words + 1) ] + tweak[ (subkey + 1) % 3 ] );
    key_schedule[ subkey_index + (Number_Words - 1) ] = ( key[ (subkey + (Number_Words - 1)) % (Number_Words + 1) ] + static_cast<uint64_t>( subkey ) );
  }

  // clear sensitive memory
  explicit_bzero( key  , sizeof(key)   );
  explicit_bzero( tweak, sizeof(tweak) );
}

template <size_t KEY_BITS>
void Threefish_Precomputed_Keyschedule<KEY_BITS>::add_subkey(const int round)
{
  const int subkey = round / 4;
  const int offset = subkey * Number_Words;
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] = (state[i] + key_schedule[ offset + i ]);
  }
}

template <size_t KEY_BITS>
void Threefish_Precomputed_Keyschedule<KEY_BITS>::subtract_subkey(const int round)
{
  const int subkey = round / 4;
  const int offset = subkey * Number_Words;
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] = (state[i] - key_schedule[ offset + i ]);
  }
}

template <size_t KEY_BITS>
void Threefish_Precomputed_Keyschedule<KEY_BITS>::cipher(const uint64_t *in, uint64_t *out)
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
      uint64_t state_copy[ Number_Words ];
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
void Threefish_Precomputed_Keyschedule<KEYSIZE>::inverse_cipher(const uint64_t *in, uint64_t *out)
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
    for( int j = 0; j<= (Number_Words / 2) - 1; ++j )
      inverse_MIX( (state + (2 * j)), (state + (2 * j) + 1), round, j );
    if( round % 4 == 0 )
      subtract_subkey( round );
  }
  std::memcpy( out, state, sizeof(state) );
}

template <size_t KEY_BITS>
uint64_t Threefish_Precomputed_Keyschedule<KEY_BITS>::permute_index(const int i) const
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
uint64_t Threefish_Precomputed_Keyschedule<KEY_BITS>::inverse_permute_index(const int i) const
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
