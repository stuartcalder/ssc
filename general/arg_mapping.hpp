#pragma once
#include <cstdio>
#include <utility>
#include <string>
#include <vector>

class Arg_Mapping
{
public:
/* PUBLIC CONSTANTS & ALIASES */
  using Arg_Map_t = std::vector< std::pair< std::string, std::string > >;
/* PUBLIC INTERFACE */
  void          print_mapping() const;
  void          parse_c_args(const int argc, const char * argv[]);
  inline void   clear();
  inline auto get() const -> const Arg_Map_t &;
  inline auto consume() -> Arg_Map_t;
/* CONSTRUCTOR(S) */
  Arg_Mapping(const int argc, const char * argv[]);
private:
/* PRIVATE DATA */
  Arg_Map_t mapping;
/* PRIVATE INTERFACE */
  bool is_option     (const std::string & str) const;
};
