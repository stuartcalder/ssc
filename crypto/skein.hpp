#ifndef SKEIN_HPP
#define SKEIN_HPP

#include "threefish.hpp"

template< size_t Block_Bits >
class Skein
{
public:
  static constexpr const size_t State_Bytes = Block_Bits / 8;

  Skein(ThreeFish<Block_Bits> &&tf);
private:
  void UBI(const uint64_t * const starting_val,
           const uint8_t  * const message,
           const uint8_t  * const tweak);
};


template< size_t Block_Bits >
Skein<Block_Bits>::Skein(ThreeFish<Block_Bits> &&tf)
  : threefish{ tf }
{
}
template< size_t Block_Bits >
void Skein<Block_Bits>::UBI(const uint64_t * const starting_val,
                            const uint64_t * const message,
                            const  uint8_t * const tweak)
{

}

#endif
