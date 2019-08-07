#pragma once
#include <cstring>
#include <iostream>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>

#if defined( __gnu_linux__ )
    #include <endian.h>
#else
    #error "Unimplemented on anything but Gnu/Linux"
#endif

#if 0 // Disable AES code for now
namespace ssc
{
    template <std::size_t KEYBITS = 256>
    class AES
    {  /* AES<int> Begin ------------------------------------------------------------------- */
    public:
        /************************** PUBLIC CONSTANTS ****************************************/
        static_assert( (KEYBITS == 128 || KEYBITS == 192 || KEYBITS == 256),
                       "KEYBITS for AES must be 128, 192, or 256 bits" );       // Disallow invalid KEYBITSs
        static constexpr std::size_t Nb = 4;                                            // Number of columns (32-bit words) comprising the state
        static constexpr std::size_t Nk = KEYBITS / 32;                                 // Number of 32-bit words comprising the cipher key
        static constexpr std::size_t Nr = Nk + 6;
        /************************** PUBLIC FUNCTIONS ****************************************/
        //Constructors
        AES() = delete;           // Disallow construction without argument
        AES(const u8 key[]); // Allow construction WITH a key only
        //Destructor
        ~AES();
        void cipher(const u8  in[],         // sizeof = 4 * Nb = 128 bits, 16 bytes
                          u8 out[]);        // sizeof = 4 * Nb = 128 bits, 16 bytes
        void inverse_cipher(const u8 in[], // sizeof = 4 * Nb = 128 bits, 16 bytes
                                  u8 out[]);// sizeof = 4 * Nb = 128 bits, 16 bytes
        void debug();
    private:
        /************************** INTERNAL CONSTANTS ****************************************/
        static constexpr u8 s_box[16][16] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };
        static constexpr u8 inv_s_box[16][16] = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };
        static constexpr u32 Rcon[] = {
            0x00'00'00'00,
            0x01'00'00'00,
            0x02'00'00'00,
            0x04'00'00'00,
            0x08'00'00'00,
            0x10'00'00'00,
            0x20'00'00'00,
            0x40'00'00'00,
            0x80'00'00'00,
            0x1b'00'00'00,
            0x36'00'00'00,
        };
        /************************** INTERNAL STATE ****************************************/
        u8  key[Nk * 4];
        u8  state[4][Nb];
        u32 key_schedule[Nb * (Nr + 1)] = { 0 };
        /************************** INTERNAL FUNCTIONS ****************************************/
        void KeyExpansion();
        void SubBytes();
        void InvSubBytes();
        void ShiftRows();
        void InvShiftRows();
        void MixColumns();
        void InvMixColumns();
        u32  SubWord(u32 word);
        u32  RotWord(u32 word);
        u8   xtime(u8 byte);
        void AddRoundKey(int round);
        
    }; /* AES<int> End ------------------------------------------------------------------ */
    
    // Constructor
    template <std::size_t KEYBITS>
    AES<KEYBITS>::AES(const u8 k[])
    {
        std::memcpy( key, k, sizeof(key) );
        KeyExpansion();
    }
    // Destructor
    template <std::size_t KEYBITS>
    AES<KEYBITS>::~AES()
    {
        // Overwrite everything private and important.
        zero_sensitive( state       , sizeof(state) );
        zero_sensitive( key         , sizeof(key) );
        zero_sensitive( key_schedule, sizeof(key_schedule) );
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::cipher(const u8 in[], u8 out[])
    {
        std::memcpy( state, in, sizeof(state) );
        AddRoundKey(0);
        for( int round = 1; round < Nr; ++round ) {
            SubBytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(round);
        }
        SubBytes();
        ShiftRows();
        AddRoundKey(Nr);
        std::memcpy( out, state, sizeof(state) );
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::inverse_cipher(const u8 in[], u8 out[])
    {
        std::memcpy( state, in, sizeof(state) );
        AddRoundKey(Nr);
        for( int round = Nr - 1; round > 0; --round ) {
            InvShiftRows();
            InvSubBytes();
            AddRoundKey(round);
            InvMixColumns();
        }
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(0);
        std::memcpy( out, state, sizeof(state) );
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::debug()
    {
        auto cmp = [](auto a, auto b){
                       for( int col = 0; col < 4; ++col )
                           for( int row = 0; row < 4; ++row )
                               if( a[col][row] != b[col][row] ) {
                                   std::cout << "NOT THE SAME!\n";
                                   std::cout << "Index ["<<col<<"]["<<row<<"] of state has changed!\n";
                                   return;
                               }
                   };
        u8 buffer[4][4];
        std::memcpy( buffer, state, sizeof(buffer) );
        std::cout << "Doing SubBytes\n";
        SubBytes();
        std::cout << "Doing InvSubBytes\n";
        InvSubBytes();
        cmp(state, buffer);
        std::memcpy( buffer, state, sizeof(buffer) );
        std::cout << "Doing ShiftRows\n";
        ShiftRows();
        std::cout << "Doing InvShiftRows\n";
        InvShiftRows();
        cmp(state, buffer);
        std::memcpy( buffer, state, sizeof(buffer) );
        std::cout << "Doing MixColumns\n";
        MixColumns();
        std::cout << "Doing InvMixColumns\n";
        InvMixColumns();
        cmp(state,buffer);
        std::memcpy( buffer, state, sizeof(buffer) );
        
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::KeyExpansion()
    {
        u32 temp;
        int i = 0;
        while( i < Nk ) {
#if 0 // ORIGINAL IMPLEMENTATION
            key_schedule[i] = 0;
            for( int j = 0; j < 4; ++j ) {
                key_schedule[i] |= ( static_cast<u32>( key[(4*i) + j] ) << (24 - j*8) );
            }
#endif
#if 1 // CURRENT IMPLEMENTATION
            key_schedule[i] = htobe32( *(reinterpret_cast<u32*>( key + (4*i) )) );
#endif
            ++i;
        }
        i = Nk;
        while( i < Nb * (Nr+1) ) {
            temp = key_schedule[i-1];
            if( i % Nk == 0 ) {
                temp = SubWord( RotWord(temp) ) ^ Rcon[i/Nk];
            }
            else if constexpr( Nk > 6 )
                                 {
                                     if( i % Nk == 4 )
                                         temp = SubWord(temp);
                                 }
            key_schedule[i] = key_schedule[i-Nk] ^ temp;
            ++i;
        }
    }
    
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::SubBytes()
    {
        for( int col = 0; col < Nb; ++col ) {
            for ( int row = 0; row < 4; ++row) {
                state[col][row] = s_box[ state[col][row] >> 4 ][ state[col][row] & 0b0000'1111 ];
            }
        }
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::InvSubBytes()
    {
        for( int col = 0; col < Nb; ++col ) {
            for( int row = 0; row < 4; ++row ) {
                state[col][row] = inv_s_box[ state[col][row] >> 4 ][ state[col][row] & 0b0000'1111 ];
            }
        }
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::ShiftRows()
    {
        // This is pretty nasty looking.
        for( int row = 1; row < 4; ++row ) {          // For each shifted row...
            int num_shifts = row;                       // We will shift i times on the i'th row.
            while( num_shifts > 0 ) {                   // Perform all the shifts in here
                const u8 first = state[0][row];      // copy first byte into a temporary buffer
                for( int col = 0; col <= 2; ++col ) {
                    state[col][row] = state[col+1][row];      // copy rightmost bytes over to the left
                }
                state[3][row] = first;                      // move buffered first byte over all the way to the right.
                --num_shifts;                               // decrement counter
            }/*while(num_shifts>0)*/
        }/*for*/
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::InvShiftRows()
    {
        for( int row = 1; row < 4; ++row ) {
            int num_shifts = row;
            while( num_shifts > 0 ) {
                const u8 last = state[3][row];
                for( int col = 3; col >= 1; --col ) {
                    state[col][row] = state[col-1][row];
                }
                state[0][row] = last;
                --num_shifts;
            }/*while(num_shifts>0)*/
        }/*for*/
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::MixColumns()
    {
        for( int col = 0; col < Nb; ++col ) {// For each column of state
            u8 original[Nb];              // Initially, just a copy of the state of 1 column
            u8 two[Nb];             //
            /* Enumerate the xtime(origina[i]) for all elements */
            for( int i = 0; i < Nb; ++i ) {
                original[i] = state[col][i];     // Copy over the state column into `original`
                two[i] = xtime(original[i]);
            }
            state[col][0] = two[0] ^ original[3] ^ original[2] ^ two[1] ^ original[1];
            state[col][1] = two[1] ^ original[0] ^ original[3] ^ two[2] ^ original[2];
            state[col][2] = two[2] ^ original[1] ^ original[0] ^ two[3] ^ original[3];
            state[col][3] = two[3] ^ original[2] ^ original[1] ^ two[0] ^ original[0];
        }/*for(int col=0;col<Nb;++col)*/
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::InvMixColumns()
    {
        for( int col = 0; col < Nb; ++col ) {
            u8 original[Nb];
            u8 nine[Nb];
            u8 eleven[Nb];
            u8 thirteen[Nb];
            u8 fourteen[Nb];
            
            /* Enumerate nine, eleven, thirteen, fourteen */
            for( int i = 0; i < Nb; ++i ) {
                original[i] = state[col][i];
                const u8 two = xtime(original[i]);
                const u8 four = xtime(two);
                const u8 eight = xtime(four);
                
                nine[i]     = eight ^ original[i];
                eleven[i]   = eight ^ two ^ original[i];
                thirteen[i] = eight ^ four ^ original[i];
                fourteen[i] = eight ^ four ^ two;
            }
            //              (         14) + (       11) + (         13) + (      9)
            state[col][0] = (fourteen[0]) ^ (eleven[1]) ^ (thirteen[2]) ^ (nine[3]);
            state[col][1] = (fourteen[1]) ^ (eleven[2]) ^ (thirteen[3]) ^ (nine[0]);
            state[col][2] = (fourteen[2]) ^ (eleven[3]) ^ (thirteen[0]) ^ (nine[1]);
            state[col][3] = (fourteen[3]) ^ (eleven[0]) ^ (thirteen[1]) ^ (nine[2]);
        }/*for(*int col=0;col<Nb;++col)*/
    }
    template <std::size_t KEYBITS>
    u32 AES<KEYBITS>::SubWord(u32 word)
    {
#if 0 // ORIGINAL IMPLEMENTATION
        u8 bytes[4];
        for( int i = 0; i < 4; ++i ) {
            const u8 b = static_cast<u8>( word >> (24 - (i*8)) );
            bytes[i] = s_box[ b >> 4 ][ b & 0x0f ];
        }
#endif
#if 1 // CURRENT IMPLEMENTATION
        u8 bytes[4];
        (*(reinterpret_cast<u32*>( bytes ))) = htobe32( word );
        for( int i = 0; i < 4; ++i )
            bytes[i] = s_box[ bytes[i] >> 4 ][ bytes[i] & 0x0f ];
#endif
#if 0 // ORIGINAL IMPLEMENTATION
        return (
                (static_cast<u32>( bytes[0] ) << 24 ) |
                (static_cast<u32>( bytes[1] ) << 16 ) |
                (static_cast<u32>( bytes[2] ) << 8  ) |
                (static_cast<u32>( bytes[3] ))
                );
#endif
#if 1 // CURRENT IMPLEMENTATION
        return htobe32( *(reinterpret_cast<u32*>( bytes )) );
#endif
    }
    template <std::size_t KEYBITS>
    u32 AES<KEYBITS>::RotWord(u32 word)
    {
        return (word >> 24) | (word << 8);
    }
    template <std::size_t KEYBITS>
    u8 AES<KEYBITS>::xtime(u8 byte)
    {
        const u8 high = static_cast<u8>( static_cast<i8>( byte ) >> 7 );
        return (byte << 1) ^ (0x1b & high);
    }
    template <std::size_t KEYBITS>
    void AES<KEYBITS>::AddRoundKey(int round)
    {
        for( int col = 0; col < 4; ++col ) {
            const int ks_index = (round*Nb) + col;
            for( int i = 0; i < 4; ++i ) {
                state[col][i] ^= static_cast<u8>( key_schedule[ks_index] >> (24 - (i*8)) );
            }
        }
    }
}
#endif
