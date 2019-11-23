/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>

#include <utility>
#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/sensitive_buffer.hh>

namespace ssc {
	template <typename Block_Cipher_t, size_t Block_Bits>
	class CounterMode {
		public:
			static_assert (CHAR_BIT == 8);
			/* Compile-Time Constants and checks*/
			static_assert (Block_Bits % CHAR_BIT == 0);
			static_assert (Block_Bits >= 128);
			static_assert (Block_Cipher_t::Block_Bits == Block_Bits);
			static constexpr size_t const Block_Bytes = Block_Bits / CHAR_BIT;
			static_assert (Block_Bytes % 2 == 0);
			static constexpr size_t const Nonce_Bytes = Block_Bytes / 2;

			/* Public Interface */
			CounterMode (void) = delete;

			CounterMode (Block_Cipher_t *cipher_p);

			CounterMode (Block_Cipher_t *cipher_p, void const *nonce);

			~CounterMode (void);

			inline void
			set_nonce (void *nonce);

			void
			xorcrypt (void *output, void const *input, size_t const input_size, u64_t start = 0);
		private:
			Block_Cipher_t	*blk_cipher_p;
			u8_t		random_nonce	[Nonce_Bytes];
	};

	template <typename Block_Cipher_t, size_t Block_Bits>
	CounterMode<Block_Cipher_t,Block_Bits>::CounterMode (Block_Cipher_t *cipher_p)
		: blk_cipher_p{ cipher_p }
	{
		obtain_os_entropy( random_nonce, sizeof(random_nonce) );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	CounterMode<Block_Cipher_t,Block_Bits>::CounterMode (Block_Cipher_t *cipher_p, void const *nonce)
		: blk_cipher_p{ cipher_p }
	{
		set_nonce( nonce );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	CounterMode<Block_Cipher_t,Block_Bits>::~CounterMode (void) {
		zero_sensitive( buffer, sizeof(buffer) );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	void
	set_nonce (void *nonce) {
		std::memcpy( random_nonce, nonce, sizeof(random_nonce) );
	}

	template <typename Block_Cipher_t, size_t Block_Bits>
	void
	CounterMode<Block_Cipher_t,Block_Bits>::xorcrypt (void *output, void const *input, size_t const input_size, u64_t start); {
		using std::memcpy, std::memset;
		u8_t					keystream_plaintext [Block_Bytes];
		Sensitive_Buffer<u8_t, Block_Bytes>	buffer;
		size_t					bytes_left = input_size;
		u8_t const				*in  = input;
		u8_t					*out = output;
		u64_t					counter = start;

		// Zero the space between the counter and the nonce.
		if constexpr(sizeof(counter) != Nonce_Bytes)
			memset( (keystream_plaintext + sizeof(counter)), 0, (Nonce_Bytes - sizeof(counter)) );
		// Copy the nonce into the second half of the keystream_plaintext.
		static_assert (sizeof(keystream_plaintext)    == Nonce_Bytes * 2);
		static_assert (sizeof(random_nonce) == Nonce_Bytes);
		memcpy( (keystream_plaintext + Nonce_Bytes), random_nonce, sizeof(random_nonce) );
		static_assert (Nonce_Bytes > sizeof(u64_t));

		while (bytes_left >= Block_Bytes) {
			// Copy the counter into the keystream_plaintext.
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			// Encrypt a block of keystream_plaintext.
			blk_cipher_p->cipher( buffer.get(), keystream_plaintext );
			// xor that block of keystream_plaintext with a block of inputtext.
			xor_block<Block_Bits>( buffer.get(), in );
			// Copy the post-xor-text out.
			memcpy( out, buffer.get(), buffer.size() );

			// Advance the input and output pointers, reduce the bytes_left counter,
			// increment the keystream_plaintext counter.
			in         += Block_Bytes;
			out        += Block_Bytes;
			bytes_left -= Block_Bytes;
			++counter;
		}
		// There is now less than one block left to xorcrypt.
		if (bytes_left > 0) {
			memcpy( keystream_plaintext, &counter, sizeof(counter) );
			// Encrypt the last block to xor with.
			blk_cipher_p->cipher( buffer.get(), keystream_plaintext );
			// For each byte left, xor them all together.
			for (int i = 0; i < static_cast<int>(bytes_left); ++i)
				buffer[ i ] ^= in[ i ];
			// Copy the post-xor-text out.
			memcpy( out, buffer.get(), bytes_left );
		}

	}
}/*namespace ssc*/
#if 0 // Disable ctr for now
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
#endif
