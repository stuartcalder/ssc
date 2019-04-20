#pragma once
#include <cstdio>
#include <utility>
#include <string>
#include <vector>

class Arg_Mapping
{
public:
/* PUBLIC INTERFACE */
  void parse_c_args(const int argc, const char * argv[]);
  inline void clear();
  void print_mapping() const;
/* CONSTRUCTOR(S) */
  Arg_Mapping(const int argc, const char * argv[]);
private:
/* PRIVATE DATA */
  std::vector< std::pair< std::string, std::string > > mapping;
/* PRIVATE INTERFACE */
  bool is_option     (const std::string & str) const;
};
