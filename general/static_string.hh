#pragma once

#include <cstddef>

#define DLL_API
#if defined( _WIN32 )
    #if defined( BUILD_DLL )
        #define DLL_API __declspec(dllexport)
    #else
        #define DLL_API __declspec(dllimport)
    #endif
#endif

namespace ssc
{
    template <std::size_t Array_Size>
    DLL_API constexpr std::size_t static_strlen(const char (&str)[Array_Size])
    {
        return Array_Size - 1;
    }
    template <std::size_t Array_Size>
    DLL_API constexpr bool static_strcmp(const char (&s0)[Array_Size],
                                         const char (&s1)[Array_Size])
    {
        for ( std::size_t i = 0; i < Array_Size; ++i )
        {
            if ( s0[ i ] != s1[ i ] )
                return false;
        }
        return true;
    }
}
