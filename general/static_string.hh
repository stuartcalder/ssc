#pragma once

namespace ssc
{
    template< size_t Array_Size >
    constexpr size_t static_strlen( const char (&str)[ Array_Size ] )
    {
        return Array_Size - 1;
    }
}
