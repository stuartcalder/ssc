#pragma once
#include <utility>
#include <string>
#include <vector>

class Arg_Mapping
{
public:
/* CONSTANTS & ALIASES */
  static constexpr const bool Debug = true;
/* PUBLIC INTERFACE */
  void parse(const int argc, const char * argv[]);
private:
/* PRIVATE DATA */
  std::vector< std::pair< std::string, std::string > > mapping;
/* PRIVATE INTERFACE */
  bool is_option     (const std::string & str) const;
};
