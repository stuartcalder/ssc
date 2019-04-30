#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include "skein.hpp"

void SSPKDF(uint8_t * const derived_key,
            const uint8_t * const password,
            const int password_length,
            const uint8_t * const salt,
            const int number_iterations,
            const int number_concatenations);
