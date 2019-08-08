#pragma once
#include <cstdint>
#include <cstdio>
#include <ssc/general/symbols.hh>

namespace ssc
{
    DLL_PUBLIC void print_binary_buffer( const uint8_t * buffer, const size_t num_bytes );
    
    template< typename integral_t >
        void print_integral_buffer( integral_t * const i_buf, size_t const num_elements );
}/* ! namespace isc */
