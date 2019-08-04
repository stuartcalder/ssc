#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <ssc/general/integers.hh>

#define MS_API
#ifdef _WIN64
    #if defined( SSC_EXPORTS )
        #define MS_API __declspec(dllexport)
    #else
        #define MS_API __declspec(dllimport)
    #endif
#endif

namespace ssc
{
    static_assert(sizeof(int) >= sizeof(u32_t));
    MS_API void SSPKDF(u8_t * const       __restrict derived_key,
                       char const * const __restrict password,
                       int const                     password_length,
                       u8_t const * const __restrict salt,
                       u32_t const                   number_iterations,
                       u32_t const                   number_concatenations);
}
