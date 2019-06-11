#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <utility>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>

/* 
  CBC < Block_Cipher_t, Block_Bits >
  This class implements The Cipher-Block-Chaining mode of operation for cryptographic block ciphers.
  Block_Cipher_t  =====> Some type that implements four specific methods:
  std::size_t encrypt(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv);
  If IV is nullptr, the "state" is assumed to be already seeded with past invocations
  If IV is not nullptr, it is used to seed the state for encryption
  std::size_t decrypt(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv);
  If IV is nullptr, the "state" is assumed to be already seeded with past invocations
  If IV is not nullptr, it is used to seed the state for encryption
  void   encrypt_no_padding(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv);
  Same IV conditions as above ; does not do any sort of padding ; must only be used with buffers
  perfectly divisible by Block_Bits
  void   decrypt_no_padding(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv);
  Same conditions as above.
  * Block_Bits      =====> a std::size_t unsigned integer describing the number of bits in 1 block of the block cipher.
  */
namespace ssc
{
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    class CBC
    {
    public:
        /* COMPILE TIME CHECKS */
        static_assert( (Block_Bits >= 128)   , "Modern block ciphers have at least 128-bit blocks!"                );
        static_assert( (Block_Bits % 8 == 0 ), "Block size must be a multiple of 8! A 'byte' must be 8 bits here." );
        /* COMPILE TIME CONSTANTS */
        static constexpr const std::size_t Block_Bytes = (Block_Bits / 8);
        /* PUBLIC INTERFACE */
        CBC() = delete;              // disallow argument-less construction for now
        CBC(Block_Cipher_t &&blk_c); // 
        ~CBC();
        void   manually_set_state(const u8 * const state_bytes);
        void   encrypt_no_padding(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv = nullptr);
        void   decrypt_no_padding(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv = nullptr);
        std::size_t            decrypt(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv = nullptr);
        std::size_t            encrypt(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv = nullptr);
    private:
        /* PRIVATE STATE */
        Block_Cipher_t  __blk_cipher;
        u8              __state[ Block_Bytes ] = { 0 };
        /* PRIVATE INTERFACE */
        static std::size_t        _apply_iso_iec_7816_padding(u8 *bytes, const std::size_t prepadding_size);
        static std::size_t  _count_iso_iec_7816_padding_bytes(const u8 * const bytes, const std::size_t padded_size);
        static std::size_t  _calculate_padded_ciphertext_size(const std::size_t unpadded_plaintext_size);
        static constexpr const auto & _xor_block = xor_block< Block_Bits >;
    };
    
    // CONSTRUCTORS
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    CBC<Block_Cipher_t,Block_Bits>::CBC(Block_Cipher_t &&blk_c) 
        : __blk_cipher{ blk_c }
    {
    }
    // DESTRUCTORS
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    CBC<Block_Cipher_t,Block_Bits>::~CBC()
    {
        zero_sensitive( __state, sizeof(__state) );
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    void CBC<Block_Cipher_t,Block_Bits>::manually_set_state(const u8 * const state_bytes)
    {
        std::memcpy( __state, state_bytes, sizeof(__state) );
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    std::size_t CBC<Block_Cipher_t,Block_Bits>::_apply_iso_iec_7816_padding(u8 *bytes, const std::size_t prepadding_size)
    {
        /* Here, bytes_to_add is pre-emptively decremented by 1, as padding
           at least one byte is necessary for this padding scheme. */
        using namespace std;
        const size_t bytes_to_add = ( Block_Bytes - (prepadding_size % Block_Bytes) - 1 );
        bytes[ prepadding_size ] = 0x80u; // The byte 0x80 precedes any null bytes (if any) that make up the padding.
        memset( (bytes + prepadding_size + 1), 0x00u, bytes_to_add );
        return prepadding_size + 1 + bytes_to_add;
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    std::size_t CBC<Block_Cipher_t,Block_Bits>::_count_iso_iec_7816_padding_bytes(const u8 * const bytes, const std::size_t padded_size)
    {
        using namespace std;
        size_t count = 0;
        for ( size_t i = padded_size - 1; padded_size > 0; --i ) {
            ++count;
            if ( bytes[i] == 0x80 )
                return count;
        }
        fprintf( stderr, "ERROR: Invalid CBC padding!\n" );
        exit( EXIT_FAILURE );
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    std::size_t CBC<Block_Cipher_t,Block_Bits>::_calculate_padded_ciphertext_size(const std::size_t unpadded_plaintext_size)
    {
        return unpadded_plaintext_size + (Block_Bytes - (unpadded_plaintext_size % Block_Bytes));
    }
    
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    void CBC<Block_Cipher_t,Block_Bits>::encrypt_no_padding(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv)
    {
        using std::memcpy;
        
        if ( iv != nullptr )
            memcpy( __state, iv, sizeof(__state) );
        if ( bytes_in != bytes_out )
            memcpy( bytes_out, bytes_in, size_in );
        const std::size_t last_block_offset = size_in - Block_Bytes;
        for ( std::size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes ) {
            u8 *current_block = bytes_out + b_off;
            _xor_block( current_block, __state );
            __blk_cipher.cipher( current_block, current_block );
            memcpy( __state, current_block, sizeof(__state) );
        }
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    std::size_t CBC<Block_Cipher_t,Block_Bits>::encrypt(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv)
    {
#if 0
        using std::memcpy;
        // If an IV was supplied, copy it into the state
        if ( iv != nullptr )
            memcpy( __state, iv, sizeof(__state) );
        // Copy the input bytes to the output buffer, plain
        if ( bytes_in != bytes_out )
            memcpy( bytes_out, bytes_in, size_in );
        // Pad the plaintext currently in the output buffer and store the padded size
        const std::size_t padded_size = _apply_iso_iec_7816_padding( bytes_out, size_in );
        // The offset of the last block is at (padded_size - Block_Bytes)
        const std::size_t last_block_offset = padded_size - Block_Bytes;
        // Iterate over every block
        for ( std::size_t block_offset = 0; block_offset <= last_block_offset; block_offset += Block_Bytes ) {
            // The "current block" we are dealing with is at (the output buffer) + (the current block offset)
            u8 *current_block = bytes_out + block_offset;
            // xor this block of output buffer with the state, and store the result in that block of the output buffer
            _xor_block( current_block, __state );
            // Call the block cipher. Encrypt the current block of the output buffer and store the ciphertext in that same block of the output buffer
            __blk_cipher.cipher( current_block, current_block );
            // Copy the current block of the output buffer into the state, to be xor'd with the next block (if there is one)
            memcpy( __state, current_block, sizeof(__state) );
        }
        // Return the number of bytes of ciphertext
        return padded_size;
#endif
        using namespace std;
        // If an IV was supplied, copy it into the state
        if ( iv != nullptr )
            memcpy( __state, iv, sizeof(__state) );
        const size_t ciphertext_size = _calculate_padded_ciphertext_size( size_in );
        size_t bytes_left = size_in;
        const u8 * in  = bytes_in;
        u8 * out = bytes_out;
        u8 buffer[ Block_Bytes ];
        while ( bytes_left >= Block_Bytes ) {
            static_assert( sizeof(buffer) == Block_Bytes );
            memcpy( buffer, in, Block_Bytes );
            _xor_block( buffer, __state );
            __blk_cipher.cipher( buffer, buffer );
            static_assert( sizeof(__state) == sizeof(buffer) );
            memcpy( __state, buffer, Block_Bytes );
            memcpy( out    , buffer, Block_Bytes );

            in         += Block_Bytes;
            out        += Block_Bytes;
            bytes_left -= Block_Bytes;
        }
        // Padding Plaintext before a final encrypt
        {
            memcpy( buffer, in, bytes_left );
            buffer[ bytes_left ] = 0x80;
            memset( (buffer + bytes_left + 1), 0, Block_Bytes - bytes_left - 1);
        }
        // Final encrypt
        _xor_block( buffer, __state );
        __blk_cipher.cipher( buffer, buffer );
        memcpy( __state, buffer, Block_Bytes );
        memcpy( out    , buffer, Block_Bytes );
        zero_sensitive( buffer, sizeof(buffer) );
        return ciphertext_size;
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    std::size_t CBC<Block_Cipher_t,Block_Bits>::decrypt(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv)
    {
        using std::memcpy;
        
        if ( iv != nullptr )
            memcpy( __state, iv, sizeof(__state) );
        const std::size_t last_block_offset = (size_in >= Block_Bytes) ? (size_in - Block_Bytes) : 0;
        u8 ciphertext[ Block_Bytes ];
        u8 buffer    [ Block_Bytes ];
        for ( std::size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes ) {
            const u8 *block_in  = bytes_in  + b_off;
            u8       *block_out = bytes_out + b_off;
            memcpy( ciphertext, block_in, sizeof(ciphertext) );
            __blk_cipher.inverse_cipher( ciphertext, buffer );
            _xor_block( buffer, __state );
            memcpy( block_out, buffer, sizeof(buffer) );
            memcpy( __state, ciphertext, sizeof(__state) );
        }
        zero_sensitive( buffer    , sizeof(buffer) );
        zero_sensitive( ciphertext, sizeof(ciphertext) );
        return size_in - _count_iso_iec_7816_padding_bytes( bytes_out, size_in );
    }
    template< typename Block_Cipher_t, std::size_t Block_Bits >
    void CBC<Block_Cipher_t,Block_Bits>::decrypt_no_padding(const u8 *bytes_in, u8 *bytes_out, const std::size_t size_in, const u8 *iv)
    {
        using std::memcpy;
        
        if ( iv != nullptr )
            memcpy( __state, iv, sizeof(__state) );
        const std::size_t last_block_offset = size_in - Block_Bytes;
        u8 ciphertext[ Block_Bytes ];
        u8 buffer    [ Block_Bytes ];
        for ( std::size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes ) {
            const u8 *block_in  = bytes_in  + b_off;
            u8       *block_out = bytes_out + b_off;
            memcpy( ciphertext, block_in, sizeof(ciphertext) );
            __blk_cipher.inverse_cipher( ciphertext, buffer );
            _xor_block( buffer, __state );
            memcpy( block_out, buffer, sizeof(buffer) );
            memcpy( __state, ciphertext, sizeof(__state) );
        }
        zero_sensitive( buffer    , sizeof(buffer) );
        zero_sensitive( ciphertext, sizeof(ciphertext) );
    }
}
