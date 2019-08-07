#pragma once
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <ssc/crypto/cbc.hh>
#include <ssc/files/files.hh>

#if 0 // Disable file_encryption for now
namespace ssc
{
    template< typename Block_Cipher_t, size_t Block_Bits >
    void cbc_encrypt_file(const char * const input_filename,
                          const char * const output_filename,
                          const uint8_t * const key,
                          const uint8_t * const iv,
                          const size_t file_buffer_size = (1024 * 1024 * 10))
    {
        static_assert( CHAR_BIT == 8, "Char bits must be 8 in this implementation" );
        static_assert( Block_Bits % 8 == 0, "Block cipher must have a multiple of 8 bits as its block size." );
        static constexpr const size_t Block_Bytes = Block_Bits / 8;
        using CBC_t = CBC< Block_Cipher_t, Block_Bits >;
        using namespace std;
  
        /////////////////Ensure key & iv aren't nullptr and Setup CBC object////////////////
        if( key == nullptr || iv == nullptr ) {
            fprintf( stderr, "CBC encryption error: Either the key or the initialization vector was a nullptr\n"
                     "The Key: %p\n"
                     "The IV : %p\n", key, iv );
            exit( EXIT_FAILURE );
        }
        CBC_t cbc{ Block_Cipher_t{ key } };
        cbc.manually_set_state( iv );
        /////////////////Open the input file and the output file////////////////////////////
        FILE * const input_file  = fopen( input_filename, "rb" );
        FILE * const output_file = fopen( output_filename, "wb" );
        if( input_file == nullptr || output_file == nullptr ) {
            fprintf( stderr, "File I/O Error: Failed to open the input file or the output file\n"
                     "Input file is %p\n"
                     "Output file is %p\n", input_file, output_file );
            exit( EXIT_FAILURE );
        }
        /////////////////Encrypt whole blocks until the last////////////////////////////
        size_t bytes_to_encrypt = get_file_size( input_file );
        auto buffer = make_unique<uint8_t[]>( file_buffer_size );
        fwrite( iv, 1, Block_Bytes, output_file );
        while( bytes_to_encrypt > file_buffer_size ) {
            fread( buffer.get(), file_buffer_size, 1, input_file );
            cbc.encrypt_no_padding( buffer.get(), buffer.get(), file_buffer_size );
            fwrite( buffer.get(), file_buffer_size, 1, output_file );
            bytes_to_encrypt -= file_buffer_size;
        }
        /////////////////Encrypt the last//////////////////////////////////////////////
        { // +
            fread( buffer.get(), 1, bytes_to_encrypt, input_file );
            size_t encrypted = cbc.encrypt( buffer.get(), buffer.get(), bytes_to_encrypt );
            fwrite( buffer.get(), 1, encrypted, output_file );
        } // -
        ////////////////Cleanup////////////////////////////////////////////////////////
        zero_sensitive( buffer.get(), file_buffer_size );
        fclose( input_file );
        fclose( output_file );
    }
    
    template< typename Block_Cipher_t, size_t Block_Bits >
    void cbc_decrypt_file(const char * const input_filename,
                          const char * const output_filename,
                          const uint8_t * const key,
                          const size_t file_buffer_size = (1024 * 1024 * 10))
    {
        static_assert( CHAR_BIT == 8, "Char bits must be 8 in this implementation" );
        static_assert( Block_Bits % 8 == 0, "Block cipher must have a multiple of 8 bits as its block size." );
        static constexpr const size_t Block_Bytes = Block_Bits / 8;
        using CBC_t = CBC< Block_Cipher_t, Block_Bits >;
        using namespace std;
        
        if( key == nullptr ) {
            fprintf( stderr, "CBC decryption error: The key was a nullptr\n" );
            exit( EXIT_FAILURE );
        }
        /////////////////Open the input file and the output file////////////////////////////
        CBC_t cbc{ Block_Cipher_t{ key } };
        FILE * const input_file  = fopen( input_filename, "rb" );
        FILE * const output_file = fopen( output_filename, "wb" );
        //////////////////Check if files successfully opened///////////////////////////////
        if( input_file == nullptr || output_file == nullptr ) {
            fprintf( stderr, "CBC decryption error: Either the input or output file was nullptr\n"
                     "Input file is %p\n"
                     "Output file is %p\n", input_file, output_file );
            exit( EXIT_FAILURE );
        }
        ////////////////////Check if parameters make sense//////////////////////
        size_t bytes_to_decrypt = get_file_size( input_file );
        if( bytes_to_decrypt < (Block_Bytes * 2) ) {
            fprintf( stderr, "CBC decryption error: %s doesn't seem to be big enough to have been big enough to have been\n"
                     "encrypted with the expected block cipher (%zu bytes-per-block).\n", Block_Bytes );
            exit( EXIT_FAILURE );
        }
        if( (bytes_to_decrypt % Block_Bytes) != 0 ) {
            fprintf( stderr, "CBC decryption error: The input file does not appear to be a multiple of blocks for the\n"
                     "expected block cipher (%zu bytes).\n", Block_Bytes );
            exit( EXIT_FAILURE );
        }
        if( (file_buffer_size % Block_Bytes) != 0 ) {
            fprintf( stderr, "CBC decryption error: The file buffer size must be a multiple of %zu bytes.\n", Block_Bytes );
            exit( EXIT_FAILURE );
        }
        //////////////////////////////Get the initialization vector///////////////////////
        { // +
            uint8_t file_iv[ Block_Bytes ];
            bytes_to_decrypt -= fread( file_iv, 1, sizeof(file_iv), input_file );
            cbc.manually_set_state( file_iv );
        } // -
        ///////////////////////////////Decrypt/////////////////////////////////////
        auto buffer = make_unique<uint8_t[]>( file_buffer_size );
        while( bytes_to_decrypt > file_buffer_size ) {
            fread( buffer.get(), buffer.get(), 1, input_file );
            cbc.decrypt_no_padding( buffer.get(), buffer.get(), file_buffer_size );
            fwrite( buffer.get(), buffer.get(), 1, output_file );
            bytes_to_decrypt -= file_buffer_size;
        }
        { // +
            fread( buffer.get(), 1, bytes_to_decrypt, input_file );
            size_t last = cbc.decrypt( buffer.get(), buffer.get(), bytes_to_decrypt );
            fwrite( buffer.get(), 1, last, output_file );
        } // -
        ///////////////////////////////////////Cleanup/////////////////////////////////////
        zero_sensitive( buffer.get(), file_buffer_size );
  
        fclose( input_file );
        fclose( output_file );
    }
}
#endif
