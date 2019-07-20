#pragma once
#include <cstdint>

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
