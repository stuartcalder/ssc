#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <ssc/general/integers.hh>

namespace ssc
{
    static_assert(sizeof(int) >= sizeof(u32_t));
    void SSPKDF(u8_t * const derived_key,
                const char * const password,
                const int password_length,
                const u8_t * const salt,
                const int number_iterations,
                const int number_concatenations);
}
