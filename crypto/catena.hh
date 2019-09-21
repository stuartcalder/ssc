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

#if 0 // Disable Catena for now
namespace ssc
{
    template< typename Hash_Func_t,
              size_t   Hash_Bits >
    class Catena
    {
    public:
        /* PUBLIC CONSTANTS */
        /* CONSTRUCTORS */
        Catena(const char *password,
               const int   password_size);
        /* PUBLIC INTERFACE */
    private:
        /* PRIVATE DATA */
        Hash_Func_t hash_func;
        /* PRIVATE INTERFACE */
    };
    
    template< typename Hash_Func_t,
              size_t   Hash_Bits >
    Catena<Hash_Func_t,Hash_Bits>::Catena(const char *password,
                                          const int   password_size)
        : __hash_func{ key }
    {}
    
    template< typename Hash_Func_t,
              size_t   Hash_Bits >
    Catena<Hash_Func_t,Hash_Bits>::
}
#endif
