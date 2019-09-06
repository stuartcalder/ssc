#pragma once
#include <cstddef>
#include <cstdint>

namespace ssc
{
    namespace ints
    {
        // Unsigned integer types
        using u8_t  = std::uint8_t;
        using u16_t = std::uint16_t;
        using u32_t = std::uint32_t;
        using u64_t = std::uint64_t;
	using std::size_t;
        // Signed types
        using i8_t  = std::int8_t;
        using i16_t = std::int16_t;
        using i32_t = std::int32_t;
        using i64_t = std::int64_t;
    }
    using namespace ints;
}
