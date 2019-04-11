#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include "crypto/aes.hpp"
#include "crypto/cbc.hpp"
#include "crypto/ctr.hpp"
#include "crypto/threefish.hpp"
#include "testing.hpp"
using namespace std;

#if 0
int main()
{
  using Cipher = ThreeFish<512>;
  constexpr int key_words = Cipher::Number_Words;

  uint64_t key[ key_words ];
  uint64_t tweak[ 2 ];
  uint64_t plaintext[ key_words ];

  uint8_t * const k = reinterpret_cast<uint8_t*>( key );
  uint8_t * const t = reinterpret_cast<uint8_t*>( tweak );
  uint8_t * const p = reinterpret_cast<uint8_t*>( plaintext );

  for( uint8_t i = 0; i <= 0x4f; ++i ) {
    k[i] = i + 0x10;
  }
  for( uint8_t i = 0; i <= 0x0f; ++i ) {
    t[i] = i;
  }
  for( uint8_t i = 0; i < sizeof(plaintext); ++i ) {
    p[i] = 0xff - i;
  }

  cout << "Key\n";
  print_uint8_buffer( reinterpret_cast<uint8_t*>( key ), sizeof(key) );
  cout << "Tweak\n";
  print_uint8_buffer( reinterpret_cast<uint8_t*>( tweak ), sizeof(tweak) );
  Cipher cipher{ key, tweak };
  cout << "Before encryption\n";
  print_uint8_buffer( reinterpret_cast<uint8_t*>( plaintext ), sizeof(plaintext) );
  cipher.encrypt( plaintext, plaintext );
  cout << "After encryption\n";
  print_uint8_buffer( reinterpret_cast<uint8_t*>( plaintext ), sizeof(plaintext) );
  cipher.decrypt( plaintext, plaintext );
  cout << "After decryption\n";
  print_uint8_buffer( reinterpret_cast<uint8_t*>( plaintext ), sizeof(plaintext) );

  return 0;
}
#endif

#if 0 // After implementing CTR mode for the first time
int main()
{
  constexpr int AES_BLOCK_BITS = 128;
  constexpr int AES_BLOCK_BYTES =  AES_BLOCK_BITS / 8;

  uint8_t key[16] = {
    0x10, 0x01, 0x02, 0x03,
    0x54, 0x05, 0x06, 0x07,
    0x28, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
  };
  uint64_t nonce = 0x0f'bc'8d'16'97'0c'0f'00;
  uint8_t *buffer = new uint8_t[ 1024 ];
  std::memset( buffer, 0, 1024 );
  using std::cout;
  cout << "Before encryption!\n";
  print_uint8_buffer( buffer, 1024 );

  using AES128_CTR = CTR< AES<128>, 128 >;

  AES128_CTR aes_ctr{ AES<128>{ key }, reinterpret_cast<uint8_t*>(&nonce) };
  aes_ctr.encrypt( buffer, buffer, 1024 );
  cout << "After encryption!\n";
  print_uint8_buffer( buffer, 1024 );
  aes_ctr.decrypt( buffer, buffer, 1024 );
  cout << "After decryption!\n";
  print_uint8_buffer( buffer, 1024 );

  delete[] buffer;
}
#endif

#if  1// Used to test CBC mode encryption
int main()
{
  constexpr int _3F_BLOCKSIZE = 256;
  constexpr int _3F_BLOCKBYTES = 32;
  uint8_t *kibibyte = new uint8_t[ 1024 ];
  constexpr int BUFFER_SIZES = 1024 + _3F_BLOCKBYTES;
  uint8_t *buffer = new uint8_t[ BUFFER_SIZES ];
  uint8_t *ecb_buffer = new uint8_t[ BUFFER_SIZES ];
  for( int i = 0; i < 512; ++i )
    kibibyte[i] = static_cast<uint8_t>(i);
  for( int i = 512; i < 1024; ++i )
    kibibyte[i] = static_cast<uint8_t>(i - 512);
  uint8_t iv[32]  = {
    0xfa, 0x38, 0x8c, 0x67, 0x7f, 0x3d, 0xf2, 0x7a,
    0x66, 0xb9, 0x1a, 0x24, 0xff, 0xaa, 0xbb, 0xdd,
    0x94, 0x34, 0x89, 0xbb, 0x87, 0x27, 0xb1, 0xd8,
    0x01, 0xff, 0x6d, 0x94, 0x67, 0x12, 0x52, 0x70
  };
  uint8_t key[32] = {
    0x70, 0x11, 0x22, 0x33, 0x89, 0x28, 0x27, 0x98,
    0x44, 0x55, 0x66, 0x77, 0x0f, 0x12, 0x98, 0x21,
    0x88, 0x99, 0xaa, 0xbb, 0x9f, 0x77, 0x22, 0x33,
    0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0xf3
  };
  /* SHOW BUFFER BEFORE ENCRYPTION */
  using std::cout;
  cout << "Buffer before any encryption:\n0x";
  for( int i = 0; i < 1024; ++i )
    cout << uint8_to_string( kibibyte[i] );
  cout << "\n\n";
  /* ENCRYPT THE BUFFER BLOCK BY BLOCK */
  {//+
    auto temp = new uint8_t[ _3F_BLOCKBYTES ];
    std::memset( temp, 0, _3F_BLOCKBYTES );
    CBC< ThreeFish<256>, 256 > cbc{ ThreeFish<256>{ reinterpret_cast<uint64_t*>(key) } };
    cbc.encrypt( kibibyte, ecb_buffer, 1024, temp );
    delete[] temp;
  }//-
  cout << "Buffer after encryption, block by block, with the same key:\n0x";
  for( int i = 0; i < 1024; ++i )
    cout << uint8_to_string( ecb_buffer[i] );
  cout << "\n\n";

  using _3F_256_CBC = CBC< ThreeFish<256>, 256 >;
  _3F_256_CBC cbc{ ThreeFish<256>{ reinterpret_cast<uint64_t*>(key) } };
  const size_t encrypted_size = cbc.encrypt( kibibyte, buffer, 1024, iv );

  cout << "Buffer after encryption WITH Cipher-Block-Chaining mode:\n0x";
  for( int i = 0; i < 1024 + 32; ++i )
    cout << uint8_to_string( buffer[i] );
  cout << "\n\n";
  cout << "Buffer after decryption:\n0x";
  const int real_size = cbc.decrypt( buffer, buffer, encrypted_size, iv );
  for( int i = 0; i < real_size; ++i )
    cout << uint8_to_string( buffer[i] );
  cout << "\n\n";
  delete[] kibibyte;
  delete[] buffer;
  delete[] ecb_buffer;
}
#endif

#if 0 //originally used to test the AES cipher
int main()
{
  uint8_t test_vec_plain[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
  };
  uint8_t test_vec_key[32] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f
  };
  uint8_t buffer[16] = { 0 };
  AES<256> aes{ test_vec_key };
  aes.cipher( test_vec_plain, buffer );
  std::cout << std::hex;
  std::cout << "Test Vector Plaintext:\n0x";
  for( auto c : test_vec_plain )
    std::cout << static_cast<unsigned int>( c );
  std::cout << "\nTest Vector Key:\n0x";
  for( auto c : test_vec_key )
    std::cout << static_cast<unsigned int>( c );
  std::cout << "Ciphertext:\n0x";
  for( auto c : buffer )
    std::cout << static_cast<unsigned int>( c );
  aes.inverse_cipher( buffer, buffer );
  std::cout << "After decryption:\n0x";
  for( auto c : buffer )
    std::cout << static_cast<unsigned int>( c );
  std::cout << std::endl;
  aes.debug();
}
#endif
