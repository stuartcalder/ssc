#ifndef THREEFISH_HPP
#define THREEFISH_HPP
#include <climits>
#include <cstdlib>
#include <cstring>
#include "operations.hpp"
#include "../general/print.hpp"

template< size_t Key_Bits=512 >
class Threefish
{
public:
  /* STATIC CHECKS */
  static_assert ( 
      (Key_Bits == 256 || Key_Bits == 512 || Key_Bits == 1024), "Invalid keysize" 
  );
  static_assert (
      (CHAR_BIT == 8), "This implementation needs 8-bit chars"
  );
  /* PUBLIC CONSTANTS */
  static constexpr const int       Number_Words   = Key_Bits / 64;
  static constexpr const int       Number_Rounds  = [](auto nw){ if( nw == 16 ) return 80; else return 72; }( Number_Words );
  static constexpr const int       Number_Subkeys = (Number_Rounds / 4) + 1;
  static constexpr const uint64_t  Constant_240   = 0x1bd1'1bda'a9fc'1a22;
  /* CONSTRUCTORS / DESTRUCTORS */
  Threefish() {
  }
  Threefish(const uint8_t *k, const uint8_t *tw = nullptr) {
      expand_key( k, tw );
  }
  Threefish(const uint64_t *k, const uint64_t *tw = nullptr) {
      expand_key( reinterpret_cast<const uint8_t *>(k),
                  reinterpret_cast<const uint8_t *>(tw) );
  }
  ~Threefish(); // forward declared
  /* PUBLIC FUNCTIONS */
  void cipher(const uint8_t *in, uint8_t *out);
  void cipher(const uint64_t *in, uint64_t *out) {
      cipher( reinterpret_cast<const uint8_t *>(in),
              reinterpret_cast<uint8_t *>(out) );
  }
  void inverse_cipher(const uint8_t *in, uint8_t *out);
  void inverse_cipher(const uint64_t *in, uint64_t *out) {
      inverse_cipher( reinterpret_cast<const uint8_t *>(in),
                      reinterpret_cast<uint8_t *>(out) );
  }
  void rekey(const uint8_t *new_key, const uint8_t *new_tweak = nullptr);
  void rekey(const uint64_t *new_key, const uint64_t *new_tweak = nullptr) {
      rekey( reinterpret_cast<const uint8_t *>(new_key),
             reinterpret_cast<const uint8_t *>(new_tweak) );
  }
private:
  /* PRIVATE DATA */
  uint64_t state       [ Number_Words ];
  uint64_t key_schedule[ Number_Subkeys * Number_Words ];
  /* PRIVATE FUNCTIONS */
  void     MIX                  (uint64_t *x0, uint64_t *x1, const int round, const int index) const;
  void     inverse_MIX          (uint64_t *x0, uint64_t *x1, const int round, const int index) const;
  void     expand_key           (const uint8_t *key, const uint8_t *tweak);
  void     add_subkey           (const int round);
  void     subtract_subkey      (const int round);
  uint64_t get_rotate_constant  (const int round, const int index) const;
  void     permute_state();
  void     inverse_permute_state();
};

template< size_t Key_Bits >
void Threefish<Key_Bits>::rekey(const uint8_t * new_key,
                                const uint8_t * new_tweak)
{
  expand_key( new_key, new_tweak );
}

template< size_t Key_Bits >
Threefish<Key_Bits>::~Threefish()
{
  explicit_bzero( key_schedule, sizeof(key_schedule) );
  explicit_bzero( state       , sizeof(state) );
}

template< size_t Key_Bits >
void Threefish<Key_Bits>::MIX(uint64_t *x0, uint64_t *x1, const int round, const int index) const
{
  (*x0) = ((*x0) + (*x1));
  (*x1) = ( rotate_left<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ^ (*x0) );
}

template< size_t Key_Bits >
void Threefish<Key_Bits>::inverse_MIX(uint64_t *x0, uint64_t *x1, const int round, const int index) const
{
  (*x1) = ((*x0) ^ (*x1));
  (*x1) = rotate_right<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ;
  (*x0) = (*x0) - (*x1);
}

template< size_t Key_Bits >
uint64_t Threefish<Key_Bits>::get_rotate_constant(const int round, const int index) const
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

template <size_t Key_Bits >
void Threefish<Key_Bits>::expand_key(const uint8_t *k, const uint8_t *tw)
{
  // key / tweak setup
  uint64_t key  [ Number_Words + 1 ]; // Big enough for the parity word
  std::memcpy( key, k, sizeof(state) );
  uint64_t tweak[ 3 ];
  if( tw != nullptr ) { // If a valid tweak was supplied
    std::memcpy( tweak, tw, sizeof(uint64_t) * 2 );
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
    key_schedule[ subkey_index + (Number_Words - 3) ] =  key[ (subkey + (Number_Words - 3)) % (Number_Words + 1) ] + tweak[ subkey % 3 ];
    key_schedule[ subkey_index + (Number_Words - 2) ] =  key[ (subkey + (Number_Words - 2)) % (Number_Words + 1) ] + tweak[ (subkey + 1) % 3 ];
    key_schedule[ subkey_index + (Number_Words - 1) ] =  key[ (subkey + (Number_Words - 1)) % (Number_Words + 1) ] + static_cast<uint64_t>( subkey );
  }

  // clear sensitive memory
  explicit_bzero( key  , sizeof(key)   );
  explicit_bzero( tweak, sizeof(tweak) );
}

template <size_t Key_Bits>
void Threefish<Key_Bits>::add_subkey(const int round)
{
  const int subkey = round / 4;
  const int offset = subkey * Number_Words;
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] += key_schedule[ offset + i ];
  }
}

template <size_t Key_Bits>
void Threefish<Key_Bits>::subtract_subkey(const int round)
{
  const int subkey = round / 4;
  const int offset = subkey * Number_Words;
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] -= key_schedule[ offset + i ];
  }
}

template <size_t Key_Bits>
void Threefish<Key_Bits>::cipher(const uint8_t *in, uint8_t *out)
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
    permute_state();
    add_subkey( Number_Rounds );
  }
  std::memcpy( out, state, sizeof(state) );
}

template <size_t Key_Bits>
void Threefish<Key_Bits>::inverse_cipher(const uint8_t *in, uint8_t *out)
{
  std::memcpy( state, in, sizeof(state) );
  subtract_subkey( Number_Rounds );
  for( int round = Number_Rounds - 1; round >= 0; --round ) {
    inverse_permute_state();
    for( int j = 0; j<= (Number_Words / 2) -1; ++j )
      inverse_MIX( (state + (2 * j)), (state + (2 * j) + 1), round, j );
    if( round % 4 == 0 )
      subtract_subkey( round );
  }
  std::memcpy( out, state, sizeof(state) );
}

template <size_t Key_Bits>
void Threefish<Key_Bits>::permute_state()
{
  if constexpr( Number_Words == 4 )
  {
    uint64_t w = state[1];
    state[1] = state[3];
    state[3] = w;
  }
  else if constexpr( Number_Words == 8 )
  {
    uint64_t w0, w1;
  /* Start from the left. Shift words in and out as necessary
     Starting with index 0 ...*/
    // index 0 overwrites index 6
    w0 = state[6];
    state[6] = state[0];
    // original index 6 (currently w0)
    // overwrites index 4 (saved into w1)
    w1 = state[4];
    state[4] = w0;
    // original index 4 (currently w1)
    // overwrites index 2 (saved into w0)
    w0 = state[2];
    state[2] = w1;
    // original index 2 (currently w0)
    // overwrites index 0 (doesn't need to be saved, as it was already written into state[6]
    state[0] = w0;

  /* Index 1 and 5 don't move. All that's left is to swap index 3 and index 7 */
    w0 = state[3];
    state[3] = state[7];
    state[7] = w0;
  }
  else if constexpr( Number_Words == 16 )
  {
    uint64_t w0, w1;
    // 1 overwrites 15 (stored in w0)
    w0 = state[15];
    state[15] = state[1];
    // 15 (in w0) overwrites 7 (stored in w1)
    w1 = state[7];
    state[7] = w0;
    // 7 (in w1) overwrites 9 (stored in w0)
    w0 = state[9];
    state[9] = w1;
    // 9 (in w0) overwrites 1
    state[1] = w0;

    // 3 overwrites 11 (stored in w0)
    w0 = state[11];
    state[11] = state[3];
    // 11 (in w0) overwrites 5 (stored in w1)
    w1 = state[5];
    state[5] = w0;
    // 5 (in w1) overwrites 13 (stored in w0)
    w0 = state[13];
    state[13] = w1;
    // 13 (in w0) overwrites 3
    state[3] = w0;

    // 4 and 6 are swapped
    w0 = state[4];
    state[4] = state[6];
    state[6] = w0;

    // 8 overwrites 14 (stored in w0)
    w0 = state[14];
    state[14] = state[8];
    // 14 (in w0) overwrites 12 (stored in w1)
    w1 = state[12];
    state[12] = w0;
    // 12 (in w1) overwrites 10 (stored in w0)
    w0 = state[10];
    state[10] = w1;
    // 10 (in w0) overwrites 8
    state[8] = w0;
  }
}

template <size_t Key_Bits>
void Threefish<Key_Bits>::inverse_permute_state()
{
  if constexpr( Number_Words == 4 )
  {
    permute_state();  // here, permute_state() and inverse_permute_state() are the same operation
  }
  else if constexpr( Number_Words == 8 )
  {
    uint64_t w0, w1;
  /* Starting from the left with index 0 */
    // original index 0
    // overwrites original index 2 (saved into w0)
    w0 = state[2];
    state[2] = state[0];
    // original index 2 (currently in w0)
    // overwrites original index 4 (saved into w1)
    w1 = state[4];
    state[4] = w0;
    // original index 4 (currently in w1)
    // overwrites original index 6 (saved into w0)
    w0 = state[6];
    state[6] = w1;
    // original index 6 (currently in w0)
    // overwrites original index 0 (doesnt need to be saved)
    state[0] = w0;
  /* Index 1 and 5 don't move. All that's left is to swap index 3 and index 7 */
    w0 = state[3];
    state[3] = state[7];
    state[7] = w0;
  }
  else if constexpr( Number_Words == 16 )
  {
    uint64_t w0, w1;
    // 1 overwrites 9 (stored in w0)
    w0 = state[9];
    state[9] = state[1];
    // 9 (in w0) overwrites 7 (stored in w1)
    w1 = state[7];
    state[7] = w0;
    // 7 (in w1) overwrites 15 (stored in w0)
    w0 = state[15];
    state[15] = w1;
    // 15 (in w0) overwrites 1
    state[1] = w0;

    // 3 overwrites 13 (stored in w0)
    w0 = state[13];
    state[13] = state[3];
    // 13 (in w0) overwrites 5 (stored in w1)
    w1 = state[5];
    state[5] = w0;
    // 5 (in w1) overwrites 11 (stored in w0)
    w0 = state[11];
    state[11] = w1;
    // 11 (in w0) overwrites 3
    state[3] = w0;

    // 4 and 6 are swapped
    w0 = state[4];
    state[4] = state[6];
    state[6] = w0;

    // 8 overwrites 10 (stored in w0)
    w0 = state[10];
    state[10] = state[8];
    // 10 (in w0) overwrites 12 (stored in w1)
    w1 = state[12];
    state[12] = w0;
    // 12 (in w1) overwrites 14 (stored in w0)
    w0 = state[14];
    state[14] = w1;
    // 14 (in w0) overwrites 8
    state[8] = w0;
  }
}

#endif
