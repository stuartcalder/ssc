#pragma once
#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>

namespace ssc
{
	class Bit_Reversal_Graph_F
	{
	public:
		static inline u64_t index (u64_t,u8_t const);
	};

	u64_t Bit_Reversal_Graph_F::index(u64_t i, u8_t const garlic)
	{
		i = reverse_byte_order( i );
		i = ((i & static_cast<u64_t>(0x0f0f0f0f0f0f0f0f)) << 4) |
		    ((i & static_cast<u64_t>(0xf0f0f0f0f0f0f0f0)) >> 4);
		i = ((i & static_cast<u64_t>(0x3333333333333333)) << 2) |
		    ((i & static_cast<u64_t>(0xcccccccccccccccc)) >> 2);
		i = ((i & static_cast<u64_t>(0x5555555555555555)) << 1) |
		    ((i & static_cast<u64_t>(0xaaaaaaaaaaaaaaaa)) >> 1);
		return i >> (64 - garlic);
	}
}/* ~ namespace ssc */
