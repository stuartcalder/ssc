#pragma once
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>

namespace ssc
{
    template< size_t State_Bits >
    class Skein_PRNG
    {
    public:
        static_assert( State_Bits == 256 ||
                       State_Bits == 512 ||
                       State_Bits == 1024,
                       "Skein_PRNG only defined for state sizes of 256,512,1024 bits" );
        static constexpr const size_t State_Bytes = State_Bits / 8;
        using Skein_t = Skein<State_Bits>;
        
        Skein_PRNG() = delete;
        Skein_PRNG(const uint8_t * const seed,
                   const uint64_t        seed_bytes);
        ~Skein_PRNG();
        void reseed(const uint8_t * const seed,
                    const uint64_t        seed_bytes);
        void get(uint8_t * const output_buffer,
                 const uint64_t  requested_bytes);
    private:
        uint8_t __state[ State_Bytes ];
        Skein_t __skein;
    };
    
    template< size_t State_Bits >
    Skein_PRNG<State_Bits>::Skein_PRNG(const uint8_t * const seed,
                                       const uint64_t        seed_bytes)
    {
        const uint64_t buffer_size = sizeof(__state) + seed_bytes;
        auto buffer = std::make_unique<uint8_t[]>( buffer_size );
        std::memset( buffer.get(), 0, sizeof(__state) );
        std::memcpy( buffer.get() + sizeof(__state), seed, seed_bytes );
        __skein.hash_native( __state, buffer.get(), buffer_size );
        zero_sensitive( buffer.get(), buffer_size );
    }
    
    template< size_t State_Bits >
    Skein_PRNG<State_Bits>::~Skein_PRNG()
    {
        zero_sensitive( __state, sizeof(__state) );
    }
    
    template< size_t State_Bits >
    void Skein_PRNG<State_Bits>::reseed(const uint8_t * const seed,
                                        const uint64_t        seed_bytes)
    {
        const uint64_t buffer_size = sizeof(__state) + seed_bytes;
        auto buffer = std::make_unique<uint8_t[]>( buffer_size );
        std::memcpy( buffer.get(), __state, sizeof(__state) );
        std::memcpy( buffer.get() + sizeof(__state),
                     seed,
                     seed_bytes );
        __skein.hash_native( __state, buffer.get(), buffer_size );
        zero_sensitive( buffer.get(), buffer_size );
    }
    
    template< size_t State_Bits >
    void Skein_PRNG<State_Bits>::get(uint8_t * const output_buffer,
                                     const uint64_t  requested_bytes)
    {
        const uint64_t buffer_size = sizeof(__state) + requested_bytes;
        auto buffer = std::make_unique<uint8_t[]>( buffer_size );
        __skein.hash( buffer.get(),
                      __state,
                      sizeof(__state),
                      buffer_size );
        std::memcpy( __state, buffer.get(), sizeof(__state) );
        std::memcpy( output_buffer,
                     buffer.get() + sizeof(__state),
                     requested_bytes );
        zero_sensitive( buffer.get(), buffer_size );
    }
}
