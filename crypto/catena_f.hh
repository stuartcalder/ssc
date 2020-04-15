#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/types.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/general/abstract.hh>
/* SSC Crypto Headers */
#include <ssc/crytpo/unique_block_iteration_f.hh>
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
#	define TEMPLATE_ARGS	template <typename MHF_f,\
	                                  int      Skein_Bits,\
					  int      Salt_Bits,\
					  int      Max_Password_Bits,\
					  bool     Use_Gamma = true,\
					  bool     Use_Phi   = false>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif

#ifndef CLASS
#	define CLASS	Catena_F<MHF_f,Skein_Bits,Salt_Bits,Max_Password_Bits,Use_Gamma,Use_Phi>
#else
#	error 'CLASS Already Defined'
#endif

#if    defined (INDEX_HASH_WORD) || defined (COPY_HASH_WORD) || defined (HASH_TWO_WORDS) || \
       defined (GRAPH_MEM)       || defined (TEMP_MEM)
#	error 'Some MACRO we need was already defined'
#endif
#define INDEX_HASH_WORD(ptr,index) \
	(ptr + (index * Skein_Bytes))

#define COPY_HASH_WORD(dest,src) \
	std::memcpy( dest, src, Skein_Bytes )

#define HASH_TWO_WORDS(data,dest,src) \
	Skein_f::hash_native( &(data->ubi_data), \
		              dest, \
			      src, \
			      (Skein_Bytes * 2) )

namespace ssc
{
	TEMPLATE_ARGS
	class Catena_F
	{
	public:
		static_assert (CHAR_BIT == 8);
		static_assert (Skein_Bits == 256 || Skein_Bits == 512 || Skein_Bits == 1024);

		using UBI_f      = Unique_Block_Iteration_F<Skein_Bits>;
		using UBI_Data_t = typename UBI_f::Data;
		using Skein_f    = Skein_F<Skein_Bits>;
		static_assert (std::is_same<UBI_Data_t,typename Skein_f::Data_t>::value);

		_CTIME_CONST (int)   Skein_Bytes  = Skein_Bits / CHAR_BIT;
		_CTIME_CONST (int)   Output_Bytes = Skein_Bytes;
		_CTIME_CONST (int)   Salt_Bytes   = Salt_Bits / CHAR_BIT;
		static_assert (Salt_Bytes % sizeof(u64_t) == 0,
			       "Force the salt to be divisible into 64-bit words.");
		_CTIME_CONST (int)   Max_Password_Bytes = Max_Password_Bits / CHAR_BIT;
		//                                                                                   (represented in bytes)    (represented in bytes)
		//    Hash(Version String) -> Skein_Bytes || Domain -> 1 byte || lambda -> 1 byte || output size -> 2 bytes || salt size -> 2 bytes
		//                 Tweak Size =>   H(V) || d || lambda || m || |s|
		_CTIME_CONST (int)   Tweak_Bytes  = Skein_Bytes + 1 + 1 + 2 + 2;
		/* CONSTANTS DERIVED FROM TEMPLATE ARGUMENTS */
		_CTIME_CONST (auto&) Version_ID_Hash = MHF_f::Version_ID_Hash; // The version ID hash is supplied by the memory-hard function.
		static_assert (std::is_same<std::decay<decltype(Version_ID_Hash)>::type,
				            u8_t*>::value,
			       "The Version_ID_Hash must decay into a u8_t pointer");
		static_assert (sizeof(Version_ID_Hash) == Skein_Bytes,
			       "The Version_ID_Hash must be Skein_Bytes large");

		enum class Domain_E : u8_t {
			Password_Scrambler = 0x00,
			Key_Derivation_Function = 0x01,
			Proof_Of_Work = 0x02
		};/* ~ enum class Domain_E:u8_t */
		
		Catena_F (void) = delete;

		struct Data {
			UBI_Data_t          ubi_data;
			u8_t                *graph_memory;
			alignas(u64_t) u8_t x_buffer  [Skein_Bytes];
			alignas(u64_t) u8_t salt      [Salt_Bytes];
			union {
				               u8_t tw_pw_slt [Tweak_Bytes + Max_Password_Bytes + Salt_Bytes];
				alignas(u64_t) u8_t flap      [Skein_Bytes * 3];
				alignas(u64_t) u8_t catena    [Skein_Bytes + sizeof(u8_t)];
				alignas(u64_t) u8_t phi       [Skein_Bytes * 2];
				struct {
					auto Gamma_Size = [](int size) constexpr -> int {
						if constexpr (Use_Gamma)
							return size;
						return 0;
					};
					alignas(u64_t) u8_t word_buf [Gamma_Size (Skein_Bytes * 2)];
					alignas(u64_t) u8_t rng      [Gamma_Size (ctime::Return_Largest (Skein_Bytes,Salt_Bytes)
							                          + (sizeof(u64_t) * 2))];
				} gamma;
			} temp;
		};/* ~ struct Data */

		static void call (_RESTRICT (Data *) data,
				  _RESTRICT (u8_t *) output,
				  _RESTRICT (u8_t *) password,
				  int const          password_size,
				  u8_t const         g_low,
				  u8_t const         g_high,
				  u8_t const         lambda);
	private:
		static inline void make_tweak_ (Data       *data,
				                u8_t const lambda);
		static void flap_ (Data       *data,
				   u8_t const garlic,
				   u8_t const lambda);
		static inline void gamma_ (Data       *data,
				           u8_t const garlic);
		static inline void phi_ (Data       *data,
				         u8_t const garlic);
	};/* ~ class Catena_F<...> */

	TEMPLATE_ARGS
	void CLASS::make_tweak_ (Data *data, u8_t const lambda)
	{
		u8_t *t = data->temp.tw_pw_slt;
		std::memcpy( t, Version_ID_Hash, sizeof(Version_ID_Hash) );
		t += sizeof(Version_ID_Hash);
		(*t) = static_cast<u8_t>(Domain_E::Key_Derivation_Function);
		++t;
		(*t) = lambda;
		++t;

		static_assert (Output_Bytes <= (std::numeric_limits<u16_t>::max)());
		static_assert (Salt_Bytes   <= (std::numeric_limits<u16_t>::max)());

		*(reinterpret_cast<u16_t*>(t)) = static_cast<u16_t>(Output_Bytes);
		t += sizeof(u16_t);
		*(reinterpret_cast<u16_t*>(t)) = static_cast<u16_t>(Salt_Bytes);
	}

	TEMPLATE_ARGS
	void CLASS::flap_ (Data *data,
			   u8_t const garlic,
			   u8_t const lambda)
	{
		static_assert (sizeof(data->x_buffer)  == Skein_Bytes);
		static_assert (sizeof(data->temp.flap) == (Skein_Bytes * 3));
		// Instead of implementing Hinit as described in the Catena spec, use Skein's ability to output arbitarily large data.
		// flap[ 0, 1, 2 ] <-- layout
#define TEMP_MEM  data->temp.flap
#define GRAPH_MEM data->graph_memory
		Skein_f::hash( &(data->ubi_data),
			       INDEX_HASH_WORD (TEMP_MEM,0),
			       INDEX_HASH_WORD (data->x_buffer,0),
			       Skein_Bytes,
			       (Skein_Bytes * 2) );
		// flap now holds [ {-1}, {-2}, {**} ]
		HASH_TWO_WORDS (data,
				INDEX_HASH_WORD (TEMP_MEM,1),  // 1 output hash word
				INDEX_HASH_WORD (TEMP_MEM,0)); // 2 input  hash words
		// flap now holds [ {-1}, { 0}, {**} ]
		COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM,2),
				INDEX_HASH_WORD (TEMP_MEM,0));
		// flap now holds [ {-1}, { 0}, {-1} ]
		HASH_TWO_WORDS (data,
				INDEX_HASH_WORD (TEMP_MEM,0),
				INDEX_HASH_WORD (TEMP_MEM,1));
		// flap now holds [ { 1}, { 0}, {-1} ]
		COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,0),
				INDEX_HASH_WORD (TEMP_MEM,1));
		COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,1),
				INDEX_HASH_WORD (TEMP_MEM,0));
		// flap still holds  [ { 1}, { 0}, {-1}   ]
		// graph_memory now holds [ { 0}, { 1}, {**}...]
		u64_t const max_hash_index = (static_cast<u64_t>(1) << garlic) - 1;
		if( max_hash_index > 1 ) {
			// max_hash_index is at least 2, meaning we require at least 4 hash words set in data->graph_memory
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (TEMP_MEM,2),
					INDEX_HASH_WORD (TEMP_MEM,0));
			// flap now holds      [ { 1}, { 0}, { 2}   ]
			// graph_memory still holds [ { 0}, { 1}, {**}...]
			COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,2),
					INDEX_HASH_WORD (TEMP_MEM,2));
			// flap still holds    [ { 1}, { 0}, { 2}          ]
			// graph_memory now holds   [ { 0}, { 1}, { 2}, {**}... ]
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM,1),
					INDEX_HASH_WORD (TEMP_MEM,2));
			// flap now holds      [ { 1}, { 2}, { 2}          ]
			// graph_memory still holds [ { 0}, { 1}, { 2}, {**}... ]
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM,2),
					INDEX_HASH_WORD (TEMP_MEM,0));
			// flap now holds      [ { 1}, { 2}, { 1}          ]
			// graph_memory still holds [ { 0}, { 1}, { 2}, {**}... ]
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (TEMP_MEM,0),
					INDEX_HASH_WORD (TEMP_MEM,1));
			// flap now holds      [ { 3}, { 2}, { 1}          ]
			// graph_memory still holds [ { 0}, { 1}, { 2}, {**}... ]
			COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,3),
					INDEX_HASH_WORD (TEMP_MEM,0));
			// flap still holds  [ { 3}, { 2}, { 1}                ]
			// graph_memory now holds [ { 0}, { 1}, { 2}, { 3}, {**}... ]

		}
		for( u64_t i = 4; i <= max_hash_index; ++i ) {
			// flap    holds [ {i-1}, {i-2}, {**}  ]
			// graph_memory holds [ {...}, {i-2}, {i-1} ]
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (TEMP_MEM,2),
					INDEX_HASH_WORD (TEMP_MEM,0));
			// flap    holds [ {i-1}, {i-2}, {  i}  ]
			// graph_memory holds [ {...}, {i-2}, {i-1} ]
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM,1),
					INDEX_HASH_WORD (TEMP_MEM,0));
			// flap    holds [ {i-1}, {i-1}, {  i}  ]
			// graph_memory holds [ {...}, {i-2}, {i-1} ]
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM,0),
					INDEX_HASH_WORD (TEMP_MEM,2));
			// flap    holds [ {  i}, {i-1}, {  i}  ]
			// graph_memory holds [ {...}, {i-2}, {i-1} ]
			COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,i),
					INDEX_HASH_WORD (TEMP_MEM,0));
		}
		// Optional Gamma-function call.
		if constexpr (Use_Gamma) {
			gamma_( data,
				garlic );
		}
		// Memory-hard-function call.
		MHF_f::call( GRAPH_MEM,
			     lambda ); //FIXME?
		// Phi function call.
		if constexpr (Use_Phi) {
			phi_( data,
			      garlic );
		} else {
			COPY_HASH_WORD (data->x_buffer,
					INDEX_HASH_WORD (GRAPH_MEM,max_hash_index));
		}
	}

	TEMPLATE_ARGS
	void CLASS::gamma_ (Data *data,
	                    u8_t const garlic)
	{
#define GRAPH_MEM data->graph_memory
#define TEMP_MEM  data->temp.gamma
		_CTIME_CONST (int) Salt_And_Garlic_Size = (sizeof(data->salt) + sizeof(u8_t));
		_CTIME_CONST (int) RNG_Output_Size = (Skein_Bytes + (sizeof(u64_t) * 2));
		static_assert (sizeof(data->salt) == Salt_Bytes);
		static_assert (sizeof(TEMP_MEM.rng) >= Salt_And_Garlic_Size);

		// Copy the salt into the rng buffer.
		std::memcpy( TEMP_MEM.rng,
			     data->salt,
			     sizeof(data->salt) );
		// Append the garlic to the end of the copied-in salt.
		*(TEMP_MEM.rng + sizeof(data->salt)) = garlic;
		static_assert (sizeof(TEMP_MEM.rng) >= RNG_Output_Size);
		// Hash the combined salt/garlic into a suitable initialization vector.
		Skein_f::hash_native( &(data->ubi_data),     // UBI Data
				      TEMP_MEM.rng,          // output
				      TEMP_MEM.rng,          // input
				      Salt_And_Garlic_Size );// input size
		u64_t const count = static_cast<u64_t>(1) << (((3 * garlic) + 3) / 4);
		for( u64_t i = 0; i < count; ++i ) {
			Skein_f::hash( &(data->ubi_data),   // UBI Data
				       TEMP_MEM.rng,// output
				       TEMP_MEM.rng,// input
				       Skein_Bytes,         // input size
				       RNG_Output_Size );   // output size

			_CTIME_CONST (int) J1_Offset = Skein_Bytes;
			_CTIME_CONST (int) J2_Offset = J1_Offset + sizeof(u64_t);

			u64_t const j1 = (*reinterpret_cast<u64_t*>(TEMP_MEM.rng + J1_Offset)) >> (64 - gamma);
			u64_t const j2 = (*reinterpret_cast<u64_t*>(TEMP_MEM.rng + J2_Offset)) >> (64 - gamma);
			static_assert (sizeof(TEMP_MEM.word_buf) == (Skein_Bytes * 2));
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM.word_buf, 0),
					INDEX_HASH_WORD (GRAPH_MEM        ,j1));
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM.word_buf, 1),
					INDEX_HASH_WORD (GRAPH_MEM        ,j2));
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (GRAPH_MEM        ,j1),
					INDEX_HASH_WORD (TEMP_MEM.word_buf, 0));
		}
	}/* ~ void gamma_(Data*,u8_t const) */
	TEMPLATE_ARGS
	void CLASS::phi_ (Data       *data,
			  u8_t const garlic)
	{
#define GRAPH_MEM data->graph_memory
#define TEMP_MEM  data->temp.phi
		u64_t const last_word_index = (static_cast<u64_t>(1) << garlic) - 1;
		u64_t j = (*reinterpret_cast<u64_t*>(INDEX_HASH_WORD (GRAPH_MEM,last_word_index))) >> (64 - garlic);
		COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,              0),
				INDEX_HASH_WORD (GRAPH_MEM,last_word_index));
		COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,1),
				INDEX_HASH_WORD (GRAPH_MEM,j));
		HASH_TWO_WORDS (data,
				INDEX_HASH_WORD (GRAPH_MEM,0),
				INDEX_HASH_WORD (TEMP_MEM ,0));
		for( u64_t i = 1; i <= last_word_index; ++i ) {
			j = (*reinterpret_cast<u64_t*>(INDEX_HASH_WORD (GRAH_MEM,(i-1)))) >> (64 - garlic);
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,   0 ),
					INDEX_HASH_WORD (GRAPH_MEM,(i-1)));
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,   1 ),
					INDEX_HASH_WORD (GRAPH_MEM,   j ));
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (GRAPH_MEM,i),
					INDEX_HASH_WORD (TEMP_MEM ,0));
		}
	}/* ~ void phi_(Data *,u8_t const) */

}/* ~ namespace ssc */
#undef GRAPH_MEM
#undef TEMP_MEM
#undef HASH_TWO_WORDS
#undef COPY_HASH_WORD
#undef INDEX_HASH_WORD
#undef CLASS
#undef TEMPLATE_ARGS
