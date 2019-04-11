#ifndef THREEFISH_HPP
#define THREEFISH_HPP
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "operations.hpp"
#include "testing.hpp"

template< size_t KEYBITS=512 >
class ThreeFish
{
public:
  /* STATIC CHECKS */
  static_assert ( 
      (KEYBITS == 256 || KEYBITS == 512 || KEYBITS == 1024), "Invalid keysize" 
  );
  static_assert( (CHAR_BIT == 8), "This implementation needs 8-bit chars" );
  /* PUBLIC CONSTANTS */
  static constexpr const int Number_Words = KEYBITS / 64;
  static constexpr const int Number_Rounds = [Number_Words]() {
    if( Number_Words == 16 )
      return 80;
    return 72;
  }();
  static constexpr const int Number_Subkeys = (Number_Rounds / 4) + 1;
  static constexpr const uint64_t Constant_240  = 0x1bd1'1bda'a9fc'1a22;
  static constexpr const bool debug_print = false;
  /* CONSTRUCTORS / DESTRUCTORS */
  ThreeFish() = delete;
  ThreeFish( uint64_t *k, uint64_t *tw = nullptr ) {
      expand_key( k, tw );
  }
  ~ThreeFish(); // forward declared
  /* PUBLIC FUNCTIONS */
  void cipher( const uint64_t *in, uint64_t *out ); // forward declared
  void cipher( const uint8_t *in, uint8_t *out ) {
    cipher( reinterpret_cast<const uint64_t*>(in),
            reinterpret_cast<uint64_t*>(out) );
  }
  void inverse_cipher( const uint64_t *in, uint64_t *out ); // forward declared
  void inverse_cipher( const uint8_t *in, uint8_t *out ) {
    inverse_cipher( reinterpret_cast<const uint64_t*>(in),
                    reinterpret_cast<uint64_t*>(out) );
  }
private:
  /* PRIVATE DATA */
  uint64_t state[ Number_Words ];
  uint64_t key_schedule[ Number_Subkeys * Number_Words ];
  /* PRIVATE FUNCTIONS */
  void MIX        ( uint64_t *x0, uint64_t *x1, const int round, const int index );
  void inverse_MIX( uint64_t *x0, uint64_t *x1, const int round, const int index );
  uint64_t get_rotate_constant( int round, int index );
  void expand_key(uint64_t *key, uint64_t *tweak);
  void add_subkey(int round);
  void subtract_subkey(int round);
  uint64_t permute_index( int i );
  uint64_t inverse_permute_index( int i );
};

template< size_t KEYBITS >
ThreeFish<KEYBITS>::~ThreeFish()
{
  explicit_bzero( key_schedule, sizeof(key_schedule) );
  explicit_bzero( state, sizeof(state) );
}

template< size_t KEYBITS >
void ThreeFish<KEYBITS>::MIX( uint64_t *x0, uint64_t *x1, const int round, const int index )
{
  uint64_t * const y0 = x0;
  uint64_t * const y1 = x1;

  (*y0) = ((*x0) + (*x1));
  (*y1) = ( rotate_left<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ^ (*y0) );
}

template< size_t KEYBITS >
void ThreeFish<KEYBITS>::inverse_MIX( uint64_t *x0, uint64_t *x1, const int round, const int index )
{
  uint64_t * const y0 = x0;
  uint64_t * const y1 = x1;

  (*y1) = ((*x0) ^ (*x1));
  (*y1) = rotate_right<uint64_t>( (*x1), get_rotate_constant( round, index ) ) ;
  (*y0) = (*x0) - (*y1);

}

template< size_t KEYBITS >
uint64_t ThreeFish<KEYBITS>::get_rotate_constant( int round, int index )
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

template <size_t KEYBITS >
void ThreeFish<KEYBITS>::expand_key( uint64_t *k, uint64_t *tw )
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

  if constexpr(debug_print){
    std::cout << "Key is now\n";
    print_uint8_buffer( reinterpret_cast<uint8_t*>( key ), sizeof(key) );
  }

  // Arbitrary keyschedule generation
  for( int subkey = 0; subkey < Number_Subkeys; ++subkey ) {// for each subkey
    const int subkey_index = subkey * Number_Words;
    for( int i = 0; i <= Number_Words - 4; ++i )// each word of the subkey
      key_schedule[ subkey_index + i ] = key[ (subkey + i) % (Number_Words + 1) ];
    key_schedule[ subkey_index + (Number_Words - 3) ]
      = ( key[ (subkey + (Number_Words - 3)) % (Number_Words + 1) ] + tweak[ subkey % 3 ] );
    key_schedule[ subkey_index + (Number_Words - 2) ]
      = ( key[ (subkey + (Number_Words - 2)) % (Number_Words + 1) ] + tweak[ (subkey + 1) % 3 ] );
    key_schedule[ subkey_index + (Number_Words - 1) ]
      = ( key[ (subkey + (Number_Words - 1)) % (Number_Words + 1) ] + static_cast<uint64_t>( subkey ) );
    if constexpr (false && debug_print) {
      std::cout << "on subkey round " << subkey << " it is now...\n";
      print_uint8_buffer( reinterpret_cast<uint8_t*>( key_schedule ), sizeof(key_schedule));
    }
  }
  if constexpr (debug_print) {
    std::cout << "Expanded key...\n";
    print_uint8_buffer( reinterpret_cast<uint8_t*>( key_schedule ), sizeof(key_schedule) );
    std::cout << "\n\n";
  }

  // clear sensitive memory
  explicit_bzero( key, sizeof(key) );
  explicit_bzero( tweak, sizeof(tweak) );
}

template <size_t KEYBITS>
void ThreeFish<KEYBITS>::add_subkey(int round)
{
  const int subkey = round / 4;
  const int offset = subkey * Number_Words;
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] = (state[i] + key_schedule[ offset + i ]);
  }
}

template <size_t KEYBITS>
void ThreeFish<KEYBITS>::subtract_subkey(int round)
{
  const int subkey = round / 4;
  const int offset = subkey * Number_Words;
  for( int i = 0; i < Number_Words; ++i ) {
    state[i] = (state[i] - key_schedule[ offset + i ]);
  }
}

template <size_t KEYBITS>
void ThreeFish<KEYBITS>::cipher(const uint64_t *in, uint64_t *out)
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
    }//-
  }
  add_subkey( Number_Rounds );
  std::memcpy( out, state, sizeof(state) );
}

template <size_t KEYSIZE>
void ThreeFish<KEYSIZE>::inverse_cipher(const uint64_t *in, uint64_t *out)
{
  std::memcpy( state, in, sizeof(state) );
  subtract_subkey( Number_Rounds );
  for( int round = Number_Rounds - 1; round >= 0; --round ) {
    {//+
      uint64_t state_copy[ Number_Words ];
      std::memcpy( state_copy, state, sizeof(state_copy) );
      for( int i = 0; i < Number_Words; ++i )
        state[i] = state_copy[ inverse_permute_index( i ) ];
    }//-
    for( int j = 0; j<= (Number_Words / 2) -1; ++j )
      inverse_MIX( (state + (2 * j)), (state + (2 * j) + 1), round, j );
    if( round % 4 == 0 )
      subtract_subkey( round );
  }
  std::memcpy( out, state, sizeof(state) );
}

template <size_t KEYBITS>
uint64_t ThreeFish<KEYBITS>::permute_index( int i )
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

template <size_t KEYBITS>
uint64_t ThreeFish<KEYBITS>::inverse_permute_index( int i )
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
