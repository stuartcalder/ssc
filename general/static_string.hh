/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstddef>
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>

namespace ssc
{
    template <size_t Array_Size>
    constexpr size_t static_strlen (char const (&str)[Array_Size])
    {
        return Array_Size - 1;
    }/* ~ constexpr size_t static_strlen<size_t AS>(char const (&)[AS]) */
    template <size_t Array_Size>
    constexpr bool static_strcmp (const char (&s0)[Array_Size],
                                  const char (&s1)[Array_Size])
    {
        for ( size_t i = 0; i < Array_Size; ++i )
            if ( s0[ i ] != s1[ i ] )
                return false;
        return true;
    }/* ~ constexpr bool static_strcmp<size_t AS>(char const (&)[AS], char const (&)[AS]) */
}/* ~ namespace ssc */
