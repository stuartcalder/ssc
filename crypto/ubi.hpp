#include "threefish_runtime_keyschedule.hpp"

template< typename Tweakable_Block_Cipher_t,
          size_t   State_Size >
void UBI(const uint64_t * const init,
         const uint8_t  * const message,
         const uint64_t * const starting_tweak)
{
  using TBC_t = Tweakable_Block_Cipher_t;
}
