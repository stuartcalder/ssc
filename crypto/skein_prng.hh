#pragma once
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>

namespace ssc
{
    template <std::size_t State_Bits>
    class DLL_PUBLIC Skein_PRNG
    {
    public:
        static_assert( State_Bits == 256 ||
                       State_Bits == 512 ||
                       State_Bits == 1024,
                       "Skein_PRNG only defined for state sizes of 256,512,1024 bits" );
        static constexpr const std::size_t State_Bytes = State_Bits / 8;
        using Skein_t = Skein<State_Bits>;
        
        Skein_PRNG() = delete;
        Skein_PRNG(const u8_t * const seed,
                   const u64_t        seed_bytes);
        ~Skein_PRNG();
        void reseed(const u8_t * const seed,
                    const u64_t        seed_bytes);
        void get(u8_t * const output_buffer,
                 const u64_t  requested_bytes);
    private:
        DLL_LOCAL u8_t    state [State_Bytes];
        DLL_LOCAL Skein_t skein;
    };
    
    template <std::size_t State_Bits>
    Skein_PRNG<State_Bits>::Skein_PRNG(const u8_t * const seed,
                                       const u64_t        seed_bytes)
    {
        this->reseed( seed, seed_bytes );
    }
    
    template <std::size_t State_Bits>
    Skein_PRNG<State_Bits>::~Skein_PRNG()
    {
        zero_sensitive( state, sizeof(state) );
    }
    
    template <std::size_t State_Bits>
    void Skein_PRNG<State_Bits>::reseed(const u8_t * const seed,
                                        const u64_t        seed_bytes)
    {
        const u64_t buffer_size = sizeof(state) + seed_bytes;
        auto buffer = std::make_unique<u8_t[]>( buffer_size );
        std::memcpy( buffer.get(), state, sizeof(state) );
        std::memcpy( buffer.get() + sizeof(state),
                     seed,
                     seed_bytes );
        skein.hash_native( state, buffer.get(), buffer_size );
        zero_sensitive( buffer.get(), buffer_size );
    }
    
    template <std::size_t State_Bits>
    void Skein_PRNG<State_Bits>::get(u8_t * const output_buffer,
                                     const u64_t  requested_bytes)
    {
        const u64_t buffer_size = sizeof(state) + requested_bytes;
        auto buffer = std::make_unique<u8_t[]>( buffer_size );
        skein.hash( buffer.get(),
                    state,
                    sizeof(state),
                    buffer_size );
        std::memcpy( state, buffer.get(), sizeof(state) );
        std::memcpy( output_buffer,
                     buffer.get() + sizeof(state),
                     requested_bytes );
        zero_sensitive( buffer.get(), buffer_size );
    }
}
