#pragma once
#include <cstdio>
#include <utility>
#include <string>
#include <vector>

namespace ssc
{
    class Arg_Mapping
    {
    public:
        /* PUBLIC CONSTANTS & ALIASES */
        using Arg_Map_t = std::vector< std::pair<std::string, std::string> >;
        /* PUBLIC INTERFACE */
        void print_mapping() const;
        void parse_c_args(const int argc, const char * argv[]);
        void clear();
        Arg_Map_t const & get() const;
        Arg_Map_t         consume();
        /* CONSTRUCTOR(S) */
        Arg_Mapping(const int argc, const char * argv[]);
    private:
        /* PRIVATE DATA */
        Arg_Map_t mapping;
        /* PRIVATE INTERFACE */
        bool is_option     (const std::string & str) const;
    };
}
