/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
#include <cstdio>
#include <utility>
#include <string>
#include <vector>
#include <ssc/general/macros.hh>
namespace ssc
{
    class _PUBLIC Arg_Mapping
    {
    public:
        /* PUBLIC CONSTANTS & ALIASES */
        using String_Pair_t = std::pair<std::string, std::string>;
        using Arg_Map_t = std::vector< String_Pair_t >;
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
