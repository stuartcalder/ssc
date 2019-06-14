#pragma once

namespace ssc
{
    template <std::size_t Array_Size>
    constexpr std::size_t static_strlen(const char (&str)[Array_Size])
    {
        return Array_Size - 1;
    }
}
