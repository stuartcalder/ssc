#ifndef SKEIN_HPP
#define SKEIN_HPP

#include "threefish.hpp"

template< size_t Block_Bits >
class Skein
{
public:
  static constexpr const size_t State_Bytes = Block_Bits / 8;

private:
  //Internal state
};

#endif
