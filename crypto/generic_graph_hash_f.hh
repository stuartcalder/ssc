/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/general/abstract.hh>
/* SSC Crypto Headers */
#include <ssc/crypto/unique_block_iteration_f.hh>
#include <ssc/crypto/skein_f.hh>
/* C Standard Headers */
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
/* C++ Standard Headers */
#include <limits>
#include <type_traits>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS template <int      Skein_Bits,\
	                               typename Graph_f>
#else
#	error 'TEMPLATE_ARGS already defined'
#endif

#ifndef CLASS
#	define CLASS Generic_Graph_Hash_F<Skein_Bits,Graph_f>
#else
#	error 'CLASS already defined'
#endif

#if    defined (INDEX_HASH_WORD) || defined (COPY_HASH_WORD) || defined (HASH_TWO_WORDS)
#	error 'Some MACRO we need already defined'
#endif
#define INDEX_HASH_WORD(ptr,index) \
	(ptr + (index * Skein_Bytes))

#define COPY_HASH_WORD(dest,src) \
	std::memcpy( dest, src, Skein_Bytes )

#define HASH_TWO_WORDS(ubi_ptr,dest,src) \
	Skein_f::hash_native( ubi_ptr, \
			      dest, \
			      src, \
			      (Skein_Bytes * 2) )

namespace ssc
{
	TEMPLATE_ARGS
	class Generic_Graph_Hash_F
	{
	public:
		static_assert (CHAR_BIT == 8);
		static_assert (Skein_Bits == 256 || Skein_Bits == 512 || Skein_Bits == 1024);
		_CTIME_CONST (int) Skein_Bytes = Skein_Bits / CHAR_BIT;
		_CTIME_CONST (int) Temp_Bytes = Skein_Bytes * 2;
		using UBI_f      = Unique_Block_Iteration_F<Skein_Bits>;
		using UBI_Data_t = typename UBI_f::Data;
		using Skein_f    = Skein_F<Skein_Bits>;
		static_assert (std::is_same<UBI_Data_t,typename Skein_f::Data_t>::value);
		static inline void call (UBI_Data_t *ubi_data,
				         u8_t       *temp,
				         u8_t       *graph_memory,
				         u8_t const garlic,
					 u8_t const lambda);
	};

	TEMPLATE_ARGS
	void CLASS::call (UBI_Data_t *ubi_data,
			  u8_t       *temp,
			  u8_t       *graph_memory,
			  u8_t const garlic,
			  u8_t const lambda)
	{
		u64_t const garlic_end = (static_cast<u64_t>(1) << garlic) - 1;
		for( u8_t j = 1; j <= lambda; ++j ) {
			COPY_HASH_WORD (INDEX_HASH_WORD (temp,0),
					INDEX_HASH_WORD (graph_memory,garlic_end));
			COPY_HASH_WORD (INDEX_HASH_WORD (temp,1),
					INDEX_HASH_WORD (graph_memory,Graph_f::index( static_cast<u64_t>(0), garlic )));
			// v0 <- H_first(v[2^g - 1], v[p(0)])
			HASH_TWO_WORDS (ubi_data,
					INDEX_HASH_WORD (graph_memory,0),
					INDEX_HASH_WORD (temp,0));
			for( u64_t i = 1; i <= garlic_end; ++i ) {
				// vi <- H(v[i-1] || v[p(i)])
				COPY_HASH_WORD (INDEX_HASH_WORD (temp,0),
						INDEX_HASH_WORD (graph_memory,(i-1)));
				COPY_HASH_WORD (INDEX_HASH_WORD (temp,1),
						INDEX_HASH_WORD (graph_memory,Graph_f::index( i, garlic )));
				HASH_TWO_WORDS (ubi_data,
						INDEX_HASH_WORD (graph_memory,i),
						INDEX_HASH_WORD (temp,0));
			}
		}
	}/* ~ void call(u8_t*,u8_t const,u8_t const) */
}/* ~ namespace ssc */
#undef HASH_TWO_WORDS
#undef COPY_HASH_WORD
#undef INDEX_HASH_WORD
#undef CLASS
#undef TEMPLATE_ARGS
