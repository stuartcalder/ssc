#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <utility>
#include <ssc/general/integers.hh>

namespace ssc
{
    template<typename Block_Cipher_t, int Block_Bits>
    class CTR
    {
    public:
        static_assert((Block_Bits >= 128), "Modern block ciphers use block sizes >= 128 bits.");
        static constexpr const int  Block_Bytes = Block_Bits / 8;
        static constexpr const int  Nonce_Bits  = Block_Bits - 64; //64 bit counter
        static constexpr const int  Nonce_Bytes = Nonce_Bits / 8;
        static constexpr const bool debug_print = false;
        CTR() = delete;
        CTR(Block_Cipher_t &&bc, u8_t *non);//->
        void set_nonce(u8_t *n);//->
        void encrypt(const u8_t *in, u8_t *out, const int size_in);//->
        void decrypt(const u8_t *in, u8_t *out, const int size_in);//->
    private:
        Block_Cipher_t blk_cipher;
        u8_t nonce[Nonce_Bytes];
        void xor_block(u8_t *block, const u8_t *add);//->
        void xor_stream(u8_t *stream, const u8_t *add, const int bytes);//->
        u8_t* generate_keystream(int *num_bytes, u64_t counter_start = 0);//->
    };
    template< typename Block_Cipher_t, int Block_Bits >
    void CTR<Block_Cipher_t,Block_Bits>::set_nonce( u8_t *n )
    {
        std::memcpy( nonce, n, Nonce_Bytes );
    }
    template< typename Block_Cipher_t, int Block_Bits >
    CTR<Block_Cipher_t,Block_Bits>::CTR(Block_Cipher_t &&bc, u8_t *non)
        : blk_cipher{ bc }
    {
        set_nonce( non );
    }
    
    template< typename Block_Cipher_t, int Block_Bits >
    void CTR<Block_Cipher_t,Block_Bits>::encrypt(const u8_t *in, u8_t *out, const int size_in)
    {
        u8_t *buffer = new u8_t[ size_in ];
        std::memcpy( buffer, in, size_in );
        int keystream_size = size_in;
        u8_t *keystream = generate_keystream( &keystream_size );
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
    template< typename Block_Cipher_t, int Block_Bits >
    void CTR<Block_Cipher_t,Block_Bits>::decrypt(const u8_t *in, u8_t *out, const int size_in)
    {
        // In CTR mode, encryption and decryption involve the same operations.
        encrypt( in, out, size_in );
    }
    template< typename Block_Cipher_t, int Block_Bits >
    void CTR<Block_Cipher_t,Block_Bits>::xor_block(u8_t *block, const u8_t *add )
    {
        if constexpr( Block_Bits == 128 ) {
                auto first_dword = reinterpret_cast<u64_t*>( block );
                auto second_dword = reinterpret_cast<const u64_t*>( add );
                (*first_dword) ^= (*second_dword);
                (*(first_dword + 1)) ^= (*(second_dword + 1));
            } else {
            for( int i = 0; i < Block_Bytes; ++i )
                block[i] ^= add[i];
        }
    }
    template< typename Block_Cipher_t, int Block_Bits >
    void CTR<Block_Cipher_t,Block_Bits>::xor_stream(u8_t *stream, const u8_t *add, const int bytes )
    {
        const int last_good_offset = bytes - (bytes % Block_Bytes) -1;
        int offset = 0;
        if constexpr(debug_print)
            {
                using std::cout;
                cout << "Before the stream was xor'd\n";
                print_uint8_buffer( stream, bytes );
            }
        // Xor blocks in the biggest chunks we can. Then one uint8 at a time.
        if( bytes >= Block_Bytes ) {
            for(; offset <= last_good_offset; offset += Block_Bytes ) {
                auto current_stream_block = stream + offset;
                auto current_add_block = add + offset;
                xor_block( current_stream_block, current_add_block );
            }
        }
        for(; offset < bytes; ++offset ) {
            stream[offset] ^= add[offset];
        }
        if constexpr(debug_print)
            {
                using std::cout;
                cout << "After the stream was xor'd\n";
                print_uint8_buffer( stream, bytes );
            }
    }
    template< typename Block_Cipher_t, int Block_Bits >
    u8_t* CTR<Block_Cipher_t,Block_Bits>::generate_keystream(int *num_bytes, u64_t counter_start)
    {
        const int needed_block_stream_bytes = (*num_bytes) + ((*num_bytes) % Block_Bytes);
        const int last_block_offset = needed_block_stream_bytes - Block_Bytes;
        u8_t *keystream = new u8_t[ needed_block_stream_bytes ];
        std::memset( keystream, 0, needed_block_stream_bytes );
        u8_t nonce_counter[ Block_Bytes ];
        std::memcpy( nonce_counter, nonce, Nonce_Bytes );
        u64_t * const counter = ( reinterpret_cast<u64_t*>( nonce_counter + Nonce_Bytes ) );
        
        *counter = counter_start;
        if constexpr( debug_print ) {
                using std::cout;
                cout << "The nonce before was\n";
                print_uint8_buffer( nonce_counter, sizeof(nonce_counter) );
            }
        for( int block_offset = 0; block_offset <= last_block_offset; block_offset += Block_Bytes ) {
            u8_t *current_block = keystream + block_offset;
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
