#pragma once
#include "threefish_runtime_keyschedule.hpp"

template< size_t State_Bits >
class Skein
{
public:
  static_assert(
      State_Bits == 256 || State_Bits == 512 || State_Bits == 1024,
      "Skein and Threefish only designed for 256, 512, 1024 bit-lengths."
  );
  using ThreeFish_t = ThreeFish_Runtime_Keyschedule< State_Bits >;
  static constexpr const size_t State_Bytes = State_Bits / 8;

  Skein(ThreeFish_t &&tf);
private:
  ThreeFish_t _threefish;
  void UBI(const uint64_t * const starting_val,
           const uint8_t  * const message,
           const uint8_t  * const tweak);
};


template< size_t Block_Bits >
Skein<Block_Bits>::Skein(ThreeFish<Block_Bits> &&tf)
  : _threefish{ tf }
{
}
template< size_t Block_Bits >
void Skein<Block_Bits>::UBI(const uint64_t * const starting_val,
                            const uint64_t * const message,
                            const  uint8_t * const tweak)
{

}
