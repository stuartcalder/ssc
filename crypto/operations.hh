/* operations.hh
 * No operating-system specific code here
 */
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>

namespace ssc
{
    static_assert(CHAR_BIT == 8);
    template< typename uint_t >
    uint_t rotate_left( uint_t value, uint_t count );
    template< typename uint_t >
    uint_t rotate_right( uint_t value, uint_t count );
    template< std::size_t Block_Bits >
    void xor_block(void * __restrict block, const void * __restrict add);
    
    void DLL_PUBLIC generate_random_bytes(u8_t * const buffer,
                                          std::size_t  num_bytes);
    void DLL_PUBLIC zero_sensitive(void *      buffer,
                                   std::size_t num_bytes);
}
