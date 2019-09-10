/*
Copyright 2019 Stuart Steven Calder

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
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
    class Skein_PRNG
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
        void os_reseed(u64_t const seed_bytes);
        void get(u8_t * const output_buffer,
                 const u64_t  requested_bytes);
    private:
        u8_t    state [State_Bytes];
        Skein_t skein;
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
    void Skein_PRNG<State_Bits>::os_reseed(u64_t const seed_bytes)
    {
        u64_t const buffer_size = sizeof(state) + seed_bytes;
        auto buffer = std::make_unique<u8_t[]>( buffer_size );
        std::memcpy( buffer.get(), state, sizeof(state) );
        generate_random_bytes( buffer.get() + sizeof(state), seed_bytes );
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
}/* ! namespace ssc */
