#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <utility>
#include <ssc/crypto/operations.hh>

/*
 * CBC < Block_Cipher_t, Block_Bits >
 *
 * This class implements The Cipher-Block-Chaining mode of operation for cryptographic block ciphers.
    * Block_Cipher_t  =====> Some type that implements four specific methods:
        size_t encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  If IV is nullptr, the "state" is assumed to be already seeded with past invocations
                  If IV is not nullptr, it is used to seed the state for encryption
        size_t decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  If IV is nullptr, the "state" is assumed to be already seeded with past invocations
                  If IV is not nullptr, it is used to seed the state for encryption
        void   encrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  Same IV conditions as above ; does not do any sort of padding ; must only be used with buffers
                  perfectly divisible by Block_Bits
        void   decrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv);
                  Same conditions as above.
    * Block_Bits      =====> a size_t unsigned integer describing the number of bits in 1 block of the block cipher.
    */
namespace ssc
{
    template< typename Block_Cipher_t, size_t Block_Bits >
    class CBC
    {
    public:
        /* COMPILE TIME CHECKS */
        static_assert( (Block_Bits >= 128)   , "Modern block ciphers have at least 128-bit blocks!"                );
        static_assert( (Block_Bits % 8 == 0 ), "Block size must be a multiple of 8! A 'byte' must be 8 bits here." );
        /* COMPILE TIME CONSTANTS */
        static constexpr const size_t Block_Bytes = (Block_Bits / 8);
        /* PUBLIC INTERFACE */
        CBC() = delete;              // disallow argument-less construction for now
        CBC(Block_Cipher_t &&blk_c); // 
        ~CBC();
        void   manually_set_state(const uint8_t * const state_bytes);
        void   encrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
        void   decrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
        size_t            decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
        size_t            encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv = nullptr);
    private:
        /* PRIVATE STATE */
        Block_Cipher_t  _blk_cipher;
        uint8_t         _state[ Block_Bytes ] = { 0 };
        /* PRIVATE INTERFACE */
        static size_t        _apply_iso_iec_7816_padding(uint8_t *bytes, const size_t prepadding_size);
        static size_t  _count_iso_iec_7816_padding_bytes(const uint8_t * const bytes, const size_t padded_size);
        static constexpr const auto & _xor_block = xor_block< Block_Bits >;
    };
    
    // CONSTRUCTORS
    template< typename Block_Cipher_t, size_t Block_Bits >
    CBC<Block_Cipher_t,Block_Bits>::CBC(Block_Cipher_t&& blk_c) 
        : _blk_cipher{ blk_c }
    {
    }
    // DESTRUCTORS
    template< typename Block_Cipher_t, size_t Block_Bits >
    CBC<Block_Cipher_t,Block_Bits>::~CBC()
    {
        zero_sensitive( _state, sizeof(_state) );
    }
    template< typename Block_Cipher_t, size_t Block_Bits >
    void CBC<Block_Cipher_t,Block_Bits>::manually_set_state(const uint8_t * const state_bytes)
    {
        std::memcpy( _state, state_bytes, sizeof(_state) );
    }
    template< typename Block_Cipher_t, size_t Block_Bits >
    size_t CBC<Block_Cipher_t,Block_Bits>::_apply_iso_iec_7816_padding(uint8_t *bytes, const size_t prepadding_size)
    {
        /* Here, bytes_to_add is pre-emptively decremented by 1, as padding
           at least one byte is necessary for this padding scheme. */
        const size_t bytes_to_add = ( Block_Bytes - (prepadding_size % Block_Bytes) - 1 );
        bytes[ prepadding_size ] = 0x80u; // The byte 0x80 precedes any null bytes (if any) that make up the padding.
        std::memset( (bytes + prepadding_size + 1), 0x00u, bytes_to_add );
        return prepadding_size + 1 + bytes_to_add;
    }
    template< typename Block_Cipher_t, size_t Block_Bits >
    size_t CBC<Block_Cipher_t,Block_Bits>::_count_iso_iec_7816_padding_bytes(const uint8_t * const bytes, const size_t padded_size)
    {
        size_t count = 0;
        for ( size_t i = padded_size - 1; padded_size > 0; --i ) {
            ++count;
            if ( bytes[i] == 0x80 )
                return count;
        }
        std::fprintf( stderr, "ERROR: Invalid CBC padding!\n" );
        std::exit( EXIT_FAILURE );
    }
    
    template< typename Block_Cipher_t, size_t Block_Bits >
    void CBC<Block_Cipher_t,Block_Bits>::encrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
    {
        using std::memcpy;
        
        if ( iv != nullptr )
            memcpy( _state, iv, sizeof(_state) );
        if ( bytes_in != bytes_out )
            memcpy( bytes_out, bytes_in, size_in );
        const size_t last_block_offset = size_in - Block_Bytes;
        for ( size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes ) {
            uint8_t *current_block = bytes_out + b_off;
            _xor_block( current_block, _state );
            _blk_cipher.cipher( current_block, current_block );
            memcpy( _state, current_block, sizeof(_state) );
        }
    }
    template< typename Block_Cipher_t, size_t Block_Bits >
    size_t CBC<Block_Cipher_t,Block_Bits>::encrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
    {
        using std::memcpy;
        if ( iv != nullptr )
            memcpy( _state, iv, sizeof(_state) );
        if ( bytes_in != bytes_out )
            memcpy( bytes_out, bytes_in, size_in );
        const size_t padded_size = _apply_iso_iec_7816_padding( bytes_out, size_in );
        const size_t last_block_offset = padded_size - Block_Bytes;
        for ( size_t block_offset = 0; block_offset <= last_block_offset; block_offset += Block_Bytes ) {
            uint8_t *current_block = bytes_out + block_offset;
            _xor_block( current_block, _state );
            _blk_cipher.cipher( current_block, current_block );
            memcpy( _state, current_block, sizeof(_state) );
        }
        return padded_size;
    }
    template< typename Block_Cipher_t, size_t Block_Bits >
    size_t CBC<Block_Cipher_t,Block_Bits>::decrypt(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
    {
        using std::memcpy;
        
        if ( iv != nullptr )
            memcpy( _state, iv, sizeof(_state) );
        const size_t last_block_offset = (size_in >= Block_Bytes) ? (size_in - Block_Bytes) : 0;
        uint8_t ciphertext[ Block_Bytes ];
        uint8_t buffer    [ Block_Bytes ];
        for ( size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes ) {
            const uint8_t *block_in  = bytes_in  + b_off;
            uint8_t       *block_out = bytes_out + b_off;
            memcpy( ciphertext, block_in, sizeof(ciphertext) );
            _blk_cipher.inverse_cipher( ciphertext, buffer );
            _xor_block( buffer, _state );
            memcpy( block_out, buffer, sizeof(buffer) );
            memcpy( _state, ciphertext, sizeof(_state) );
        }
        zero_sensitive( buffer    , sizeof(buffer) );
        zero_sensitive( ciphertext, sizeof(ciphertext) );
        return size_in - _count_iso_iec_7816_padding_bytes( bytes_out, size_in );
    }
    template< typename Block_Cipher_t, size_t Block_Bits >
    void CBC<Block_Cipher_t,Block_Bits>::decrypt_no_padding(const uint8_t *bytes_in, uint8_t *bytes_out, const size_t size_in, const uint8_t *iv)
    {
        using std::memcpy;
        
        if ( iv != nullptr )
            memcpy( _state, iv, sizeof(_state) );
        const size_t last_block_offset = size_in - Block_Bytes;
        uint8_t ciphertext[ Block_Bytes ];
        uint8_t buffer    [ Block_Bytes ];
        for ( size_t b_off = 0; b_off <= last_block_offset; b_off += Block_Bytes ) {
            const uint8_t *block_in  = bytes_in  + b_off;
            uint8_t       *block_out = bytes_out + b_off;
            memcpy( ciphertext, block_in, sizeof(ciphertext) );
            _blk_cipher.inverse_cipher( ciphertext, buffer );
            _xor_block( buffer, _state );
            memcpy( block_out, buffer, sizeof(buffer) );
            memcpy( _state, ciphertext, sizeof(_state) );
        }
        zero_sensitive( buffer    , sizeof(buffer) );
        zero_sensitive( ciphertext, sizeof(ciphertext) );
    }
}
