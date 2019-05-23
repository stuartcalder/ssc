#pragma once
#include <cstdint>

template< typename Hash_Func_t,
          size_t   Hash_Bits >
class Catena
{
public:
    /* PUBLIC CONSTANTS */
    /* CONSTRUCTORS */
    Catena() = delete;
    /* PUBLIC INTERFACE */
private:
    /* PRIVATE DATA */
    Hash_Func_t __hash_func;
    /* PRIVATE INTERFACE */
};

template< typename Hash_Func_t,
          size_t   Hash_Bits >
Catena<Hash_Func_t,Hash_Bits>::Catena()
    : __hash_func{ key }
{}

template< typename Hash_Func_t,
          size_t   Hash_Bits >
Catena<Hash_Func_t,Hash_Bits>::
