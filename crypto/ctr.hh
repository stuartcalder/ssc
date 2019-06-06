#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <utility>

namespace ssc
{
    template< typename block_cipher_t, int BLOCK_BITS >
    class CTR
    {
    public:
        static_assert( (BLOCK_BITS >= 128), "Modern block ciphers use block sizes >= 128 bits.");
        static constexpr const int BLOCK_BYTES = BLOCK_BITS / 8;
        static constexpr const int NONCE_BITS = BLOCK_BITS - 64; //64 bit counter
        static constexpr const int NONCE_BYTES = NONCE_BITS / 8;
        static constexpr const bool debug_print = false;
        CTR() = delete;
        CTR(block_cipher_t &&bc, uint8_t *non);//->
        void set_nonce( uint8_t *n );//->
        void encrypt(const uint8_t *in, uint8_t *out, const int size_in);//->
        void decrypt(const uint8_t *in, uint8_t *out, const int size_in);//->
    private:
        block_cipher_t blk_cipher;
        uint8_t nonce[ NONCE_BYTES ];
        void xor_block(uint8_t *block, const uint8_t *add);//->
        void xor_stream(uint8_t *stream, const uint8_t *add, const int bytes);//->
        uint8_t* generate_keystream(int *num_bytes, uint64_t counter_start = 0);//->
    };
    template< typename block_cipher_t, int BLOCK_BITS >
    void CTR<block_cipher_t,BLOCK_BITS>::set_nonce( uint8_t *n )
    {
        std::memcpy( nonce, n, NONCE_BYTES );
    }
    template< typename block_cipher_t, int BLOCK_BITS >
    CTR<block_cipher_t,BLOCK_BITS>::CTR(block_cipher_t &&bc, uint8_t *non)
        : blk_cipher{ bc }
    {
        set_nonce( non );
    }
    
    template< typename block_cipher_t, int BLOCK_BITS >
    void CTR<block_cipher_t,BLOCK_BITS>::encrypt(const uint8_t *in, uint8_t *out, const int size_in)
    {
        uint8_t *buffer = new uint8_t[ size_in ];
        std::memcpy( buffer, in, size_in );
        int keystream_size = size_in;
        uint8_t *keystream = generate_keystream( &keystream_size );
        if constexpr( debug_print ) {
                using std::cout;
                cout << "The generated keystream was ";
                print_uint8_buffer( keystream, keystream_size );
            }
        xor_stream( buffer, keystream, size_in );
        std::memcpy( out, buffer, size_in );
        
        
        delete[] keystream;
        delete[] buffer;
    }
    template< typename block_cipher_t, int BLOCK_BITS >
    void CTR<block_cipher_t,BLOCK_BITS>::decrypt(const uint8_t *in, uint8_t *out, const int size_in)
    {
        // In CTR mode, encryption and decryption involve the same operations.
        encrypt( in, out, size_in );
    }
    template< typename block_cipher_t, int BLOCK_BITS >
    void CTR<block_cipher_t,BLOCK_BITS>::xor_block(uint8_t *block, const uint8_t *add )
    {
        if constexpr( BLOCK_BITS == 128 ) {
                auto first_dword = reinterpret_cast<uint64_t*>( block );
                auto second_dword = reinterpret_cast<const uint64_t*>( add );
                (*first_dword) ^= (*second_dword);
                (*(first_dword + 1)) ^= (*(second_dword + 1));
            } else {
            for( int i = 0; i < BLOCK_BYTES; ++i )
                block[i] ^= add[i];
        }
    }
    template< typename block_cipher_t, int BLOCK_BITS >
    void CTR<block_cipher_t,BLOCK_BITS>::xor_stream(uint8_t *stream, const uint8_t *add, const int bytes )
    {
        const int last_good_offset = bytes - (bytes % BLOCK_BYTES) -1;
        int offset = 0;
        if constexpr( debug_print ) {
                using std::cout;
                cout << "Before the stream was xor'd\n";
                print_uint8_buffer( stream, bytes );
            }
        // Xor blocks in the biggest chunks we can. Then one uint8 at a time.
        if( bytes >= BLOCK_BYTES ) {
            for(; offset <= last_good_offset; offset += BLOCK_BYTES ) {
                auto current_stream_block = stream + offset;
                auto current_add_block = add + offset;
                xor_block( current_stream_block, current_add_block );
            }
        }
        for(; offset < bytes; ++offset ) {
            stream[offset] ^= add[offset];
        }
        if constexpr( debug_print ) {
                using std::cout;
                cout << "After the stream was xor'd\n";
                print_uint8_buffer( stream, bytes );
            }
    }
    template< typename block_cipher_t, int BLOCK_BITS >
    uint8_t* CTR<block_cipher_t,BLOCK_BITS>::generate_keystream(int *num_bytes, uint64_t counter_start)
    {
        const int needed_block_stream_bytes = (*num_bytes) + ((*num_bytes) % BLOCK_BYTES);
        const int last_block_offset = needed_block_stream_bytes - BLOCK_BYTES;
        uint8_t *keystream = new uint8_t[ needed_block_stream_bytes ];
        std::memset( keystream, 0, needed_block_stream_bytes );
        uint8_t nonce_counter[ BLOCK_BYTES ];
        std::memcpy( nonce_counter, nonce, NONCE_BYTES );
        uint64_t * const counter = ( reinterpret_cast<uint64_t*>( nonce_counter + NONCE_BYTES ) );
        
        *counter = counter_start;
        if constexpr( debug_print ) {
                using std::cout;
                cout << "The nonce before was\n";
                print_uint8_buffer( nonce_counter, sizeof(nonce_counter) );
            }
        for( int block_offset = 0; block_offset <= last_block_offset; block_offset += BLOCK_BYTES ) {
            uint8_t *current_block = keystream + block_offset;
            blk_cipher.cipher( nonce_counter, current_block );
            ++(*counter);
        }
        if constexpr( debug_print ) {
                using std::cout;
                cout << "The nonce after was\n";
                print_uint8_buffer( nonce_counter, sizeof(nonce_counter) );
            }
        
        (*num_bytes) = needed_block_stream_bytes;
        return keystream;
    }
}
