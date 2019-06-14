#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>

namespace ssc
{
    void SSPKDF(u8_t * const derived_key,
                const u8_t * const password,
                const int password_length,
                const u8_t * const salt,
                const int number_iterations,
                const int number_concatenations);
}
