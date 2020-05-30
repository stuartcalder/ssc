/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
/* SSC General
 */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/error_conditions.hh>
#include <ssc/general/abstract.hh>
/* SSC Crypto
 */
#include <ssc/crypto/unique_block_iteration_f.hh>
#include <ssc/crypto/skein_f.hh>
/* C Std
 */
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
/* C++ Std
 */
#include <limits>
#include <type_traits>

#if    defined (DEFAULT_ARGS)    || defined (TEMPLATE_ARGS)  || defined (CLASS)          || \
       defined (INDEX_HASH_WORD) || defined (COPY_HASH_WORD) || defined (HASH_TWO_WORDS) || \
       defined (GRAPH_MEM)       || defined (TEMP_MEM)       || defined (X_MEM)
#	error 'Some MACRO we need was already defined'
#endif

#define DEFAULT_ARGS    template <typename MHF_f,\
	                          typename Metadata_t,\
				  int      Skein_Bits,\
				  int      Salt_Bits,\
				  int      Max_Password_Bits,\
				  bool     Use_Gamma = true,\
				  bool     Use_Phi   = false>
#define TEMPLATE_ARGS	template <typename MHF_f,\
	                          typename Metadata_t,\
	                          int      Skein_Bits,\
				  int      Salt_Bits,\
				  int      Max_Password_Bits,\
				  bool     Use_Gamma,\
				  bool     Use_Phi>

#define CLASS	Catena_F<MHF_f,Metadata_t,Skein_Bits,Salt_Bits,Max_Password_Bits,Use_Gamma,Use_Phi>

#define INDEX_HASH_WORD(ptr,index) \
	(ptr + (index * Skein_Bytes))

#define COPY_HASH_WORD(dest,src) \
	std::memcpy( dest, src, Skein_Bytes )

#define HASH_TWO_WORDS(data,dest,src) \
	Skein_f::hash_native( &(data->ubi_data), \
		              dest, \
			      src, \
			      (Skein_Bytes * 2) )

namespace ssc {
	DEFAULT_ARGS class
	Catena_F
	{
	public:
	/* Compile-Time Checks and Constants
	 */
		static_assert (CHAR_BIT == 8);
		static_assert (Skein_Bits == 256 || Skein_Bits == 512 || Skein_Bits == 1024);

		using UBI_f      = Unique_Block_Iteration_F<Skein_Bits>;
		using UBI_Data_t = typename UBI_f::Data;
		using Skein_f    = Skein_F<Skein_Bits>;
		static_assert (std::is_same<UBI_Data_t,typename Skein_f::Data_t>::value);

		enum Int_Constants : int {
			Skein_Bytes  = Skein_Bits / CHAR_BIT,
			Output_Bytes = Skein_Bytes,
			Salt_Bytes   = Salt_Bits / CHAR_BIT,
			Max_Password_Bytes = Max_Password_Bits / CHAR_BIT,
	/*    Hash(Version String) -> Skein_Bytes || Domain -> 1 byte || lambda -> 1 byte || output size -> 2 bytes || salt size -> 2 bytes
	 *    Tweak Size =>   H(V) || d || lambda || m || |s|
	 */
			Tweak_Bytes  = Skein_Bytes + 1 + 1 + 2 + 2
		};
		static_assert (Salt_Bytes % sizeof(u64_t) == 0, "Force the salt to be divisible into 64-bit words.");
	/* Constants derived from template arguments.
	 */
		enum class Domain_E : u8_t {
			Password_Scrambler = 0x00,
			Key_Derivation_Function = 0x01,
			Proof_Of_Work = 0x02
		};// ~ enum class Domain_E:u8_t
		enum class Return_E {
			Success = 0,
			Alloc_Failure = 1
		};
		
		Catena_F (void) = delete;


	/* conditional_size<bool $b> (int $size) -> int
	 * 	Returns the size given some constant boolean $b, otherwise 0.
	 */
		template <bool b> static constexpr int
		Conditional_Size (int size)
		{
			if constexpr (b)
				return size;
			return 0;
		}


	/* struct Data
	 * 	Store all the stack data necessary to compute Skein512-Catena-BRG.
	 */
		struct Data {
		/* Data members needed throughout Catena's lifetime, that must remain intact until termination.
		 */
			UBI_Data_t          ubi_data;
			u8_t                *graph_memory;
			alignas(u64_t) u8_t x_buffer  [Skein_Bytes];
			alignas(u64_t) u8_t salt      [Salt_Bytes];
		/* Temporary data members. Only one of these members of this union is active at a time.
		 */
			union {
				alignas(u64_t) u8_t tw_pw_slt [Tweak_Bytes + Max_Password_Bytes + Salt_Bytes];
				alignas(u64_t) u8_t flap      [Skein_Bytes * 3];
				alignas(u64_t) u8_t catena    [Skein_Bytes + sizeof(u8_t)];
				alignas(u64_t) u8_t phi       [Skein_Bytes * 2];
				alignas(u64_t) u8_t mhf       [MHF_f::Temp_Bytes];
				struct {
					alignas(u64_t) u8_t word_buf [Conditional_Size<Use_Gamma> (Skein_Bytes * 2)];
					alignas(u64_t) u8_t rng      [Conditional_Size<Use_Gamma> (ctime::Return_Largest (Skein_Bytes,Salt_Bytes) + (sizeof(u64_t) * 2))];
				} gamma;
			} temp;
		};/* ~ struct Data */


	/* call (SSC_RESTRICT(Data*),
	 *       SSC_RESTRICT(u8_t*),
	 *       SSC_RESTRICT(u8_t*),
	 *       int const,
	 *       u8_t const,
	 *       u8_t const,
	 *       u8_t const) -> Return_E
	 *	 	Invoke Catena.
	 */
		[[nodiscard]] static Return_E
		call (SSC_RESTRICT (Data *) data,
		      SSC_RESTRICT (u8_t *) output,
	              SSC_RESTRICT (u8_t *) password,
		      int const             password_size,
		      u8_t const            g_low,
		      u8_t const            g_high,
		      u8_t const            lambda);
	private:
	/* make_tweak_ (Data*,u8_t const) -> void
	 * 	Compute, then store the tweak for the given value of $lambda.
	 */
		static inline void
		make_tweak_ (Data       *data,
		             u8_t const lambda);
	/* flap_ (Data*,u8_t const,u8_t const) -> void
	 * 	Compute the flap function for the given $garlic and $lambda.
	 */
		static void
		flap_ (Data       *data,
		       u8_t const garlic,
		       u8_t const lambda);
	/* gamma_ (Data*,u8_t const) -> void
	 * 	Compute the gamma function for the given $garlic.
	 */
		static inline void
		gamma_ (Data       *data,
		        u8_t const garlic);
	/* phi_ (Data*,u8_t const) -> void
	 * 	Compute the phi function for the given $garlic.
	 */
		static inline void
		phi_ (Data       *data,
		      u8_t const garlic);
	};// ~ class Catena_F<...>

	TEMPLATE_ARGS typename CLASS::Return_E
	CLASS::call (SSC_RESTRICT (Data *) data,
                     SSC_RESTRICT (u8_t *) output,
                     SSC_RESTRICT (u8_t *) password,
	             int const             password_size,
	             u8_t const            g_low,
	             u8_t const            g_high,
	             u8_t const            lambda)
	{
	// Dynamically allocate the memory we're going to need.
		data->graph_memory = static_cast<u8_t*>(std::malloc( (static_cast<u64_t>(1) << g_high) * Skein_Bytes ));
		if( data->graph_memory == nullptr )
			return Return_E::Alloc_Failure;
	// Setup the tweak.
		make_tweak_( data, lambda );
	// Append the password to the tweak.
		std::memcpy( data->temp.tw_pw_slt + Tweak_Bytes,
			     password,
			     password_size );
	// Destroy the password.
		zero_sensitive( password, password_size );
	// Append the salt to the password.
		std::memcpy( data->temp.tw_pw_slt + Tweak_Bytes + password_size,
			     data->salt,
			     sizeof(data->salt) );
	// Hash (tweak||password||salt) into the x buffer.
		Skein_f::hash_native( &(data->ubi_data),
				      data->x_buffer,
				      data->temp.tw_pw_slt,
				      password_size + (Tweak_Bytes + Salt_Bytes) );
	// Do an initial flap.
		flap_( data, (g_low + 1) / 2, lambda );
	// Hash the x buffer into itself.
		Skein_f::hash_native( &(data->ubi_data),
				      data->x_buffer,
				      data->x_buffer,
				      sizeof(data->x_buffer) );
		for( u8_t g = g_low; g <= g_high; ++g ) {
		// Flap.
			flap_( data, g, lambda );
		// Concatenate g and the x buffer, and hash it back into the x buffer.
			static_assert (sizeof(data->temp.catena) == (sizeof(data->x_buffer) + sizeof(u8_t)));
			*(data->temp.catena) = g;
			COPY_HASH_WORD (data->temp.catena + sizeof(u8_t),
					data->x_buffer);
			Skein_f::hash_native( &(data->ubi_data),
					      data->x_buffer,
					      data->temp.catena,
					      sizeof(data->temp.catena) );
		}
	// Zero out the used graph memory now that we have finished our flaps.
		zero_sensitive( data->graph_memory, (static_cast<u64_t>(1) << g_high) * Skein_Bytes );
	// Free the dynamically allocated graph memory.
		std::free( data->graph_memory );
		COPY_HASH_WORD (output,
				data->x_buffer);
		return Return_E::Success;
	}// ~ void call(...)

	TEMPLATE_ARGS void
	CLASS::make_tweak_ (Data *data, u8_t const lambda)
	{
		static_assert (sizeof(Metadata_t::Version_ID_Hash) == Skein_Bytes);
		static_assert (Output_Bytes <= (std::numeric_limits<u16_t>::max)());
		static_assert (Salt_Bytes   <= (std::numeric_limits<u16_t>::max)());
	// Get a pointer to the beginning of temp.tw_pw_slt.
		u8_t *t = data->temp.tw_pw_slt;
	// Copy the version_id hash in.
		std::memcpy( t, Metadata_t::Version_ID_Hash, Skein_Bytes );
	// Increment to the domain offset.
		t += sizeof(Metadata_t::Version_ID_Hash);
	 // Copy the domain offset in.
		(*t++) = static_cast<u8_t>(Domain_E::Key_Derivation_Function);
	 // Copy the lambda in.
		(*t++) = lambda;
		{
		// Use memcpy to type-pun between u8_t and u16_t.
			u16_t temp = static_cast<u16_t>(Output_Bytes);
			std::memcpy( t, &temp, sizeof(temp) );
			t += sizeof(temp);
			temp = static_cast<u16_t>(Salt_Bytes);
			std::memcpy( t, &temp, sizeof(temp) );
		}
	}// ~ void make_tweak_(Data*,u8_t const)

	TEMPLATE_ARGS void
	CLASS::flap_ (Data *data,
		      u8_t const garlic,
		      u8_t const lambda)
	{
#define TEMP_MEM  data->temp.flap
#define GRAPH_MEM data->graph_memory
#define X_MEM     data->x_buffer
		static_assert (sizeof(TEMP_MEM) == (Skein_Bytes * 3));
		static_assert (sizeof(X_MEM) == Skein_Bytes);
	/* Instead of implementing Hinit as described in the Catena spec, use Skein's ability to output arbitarily large data.
	 * flap[ 0, 1, 2 ] <-- layout
	 */
		if constexpr (Skein_Bytes == 64) {
		// For Skein512, pre-compute its initial chaining value and use it directly with UBI_F.
			alignas(u64_t) static constexpr u8_t Config [Skein_Bytes] = {
				0x54, 0x5e, 0x7a, 0x4c, 0x78, 0x32, 0xaf, 0xdb,
				0xc7, 0xab, 0x18, 0xd2, 0x87, 0xd9, 0xe6, 0x2d,
				0x41, 0x08, 0x90, 0x3a, 0xcb, 0xa9, 0xa3, 0xae,
				0x31, 0x08, 0xc7, 0xe4, 0x0e, 0x0e, 0x55, 0xa0,
				0xc3, 0x9c, 0xa8, 0x5d, 0x6c, 0xd2, 0x46, 0x71,
				0xba, 0x1b, 0x58, 0x66, 0x31, 0xa3, 0xfd, 0x33,
				0x87, 0x69, 0x83, 0x54, 0x3c, 0x17, 0x93, 0x02,
				0xd7, 0x59, 0x94, 0x61, 0x00, 0xb8, 0xb8, 0x07
			};
			std::memcpy( data->ubi_data.key_state,
				     Config,
				     sizeof(Config) );
			UBI_f::chain_message( &data->ubi_data,
					      INDEX_HASH_WORD (X_MEM,0),
					      Skein_Bytes );
			UBI_f::chain_output( &data->ubi_data,
					     INDEX_HASH_WORD (TEMP_MEM,0),
					     (Skein_Bytes * 2) );
		} else {
			Skein_f::hash( &(data->ubi_data),
				       INDEX_HASH_WORD (TEMP_MEM,0), // Output
				       INDEX_HASH_WORD (X_MEM   ,0), // Input
				       Skein_Bytes,                  // Input size
				       (Skein_Bytes * 2) );          // Output size
		}
	// flap now holds [ {-1}, {-2}, {**} ]
		HASH_TWO_WORDS (data,
			// 1 output hash word.
				INDEX_HASH_WORD (TEMP_MEM,1),
			// 2 input hash words.
				INDEX_HASH_WORD (TEMP_MEM,0));
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
	/* Optional Gamma-function call.
	 */
		if constexpr (Use_Gamma) {
			gamma_( data,
				garlic );
		}
	/* Memory-hard function call.
	 */
		MHF_f::call( &(data->ubi_data),
			     data->temp.mhf,
			     GRAPH_MEM,
			     garlic,
			     lambda );
		if constexpr (Use_Phi) {
		/* Optional Phi-function call.
		 */
			phi_( data,
			      garlic );
		} else {
		/* When Phi is not used, copy the last word of the hash array into x buffer.
		 */
			COPY_HASH_WORD (INDEX_HASH_WORD (X_MEM    ,0),
					INDEX_HASH_WORD (GRAPH_MEM,max_hash_index));
		}
#undef X_MEM
#undef GRAPH_MEM
#undef TEMP_MEM
	}// ~ void flap_ (Data*,u8_t const,u8_t const)

	TEMPLATE_ARGS void
	CLASS::gamma_ (Data       *data,
	               u8_t const garlic)
	{
#define GRAPH_MEM data->graph_memory
#define TEMP_MEM  data->temp.gamma
		static constexpr int Salt_And_Garlic_Size = (sizeof(data->salt) + sizeof(u8_t));
		static constexpr int RNG_Output_Size      = (Skein_Bytes + (sizeof(u64_t) * 2));
		static_assert (sizeof(data->salt) == Salt_Bytes);
		static_assert (sizeof(TEMP_MEM.rng) >= Salt_And_Garlic_Size);
		static_assert (sizeof(TEMP_MEM.rng) >= RNG_Output_Size);

	// Copy the salt into the rng buffer.
		std::memcpy( TEMP_MEM.rng,
			     data->salt,
			     sizeof(data->salt) );
	// Append the garlic to the end of the copied-in salt.
		*(TEMP_MEM.rng + sizeof(data->salt)) = garlic;
	// Hash the combined salt/garlic into a suitable initialization vector.
		Skein_f::hash_native( &(data->ubi_data),     // UBI Data
				      TEMP_MEM.rng,          // output
				      TEMP_MEM.rng,          // input
				      Salt_And_Garlic_Size );// input size
		u64_t const count = static_cast<u64_t>(1) << (((3 * garlic) + 3) / 4);
		for( u64_t i = 0; i < count; ++i ) {
			if constexpr (Skein_Bytes == 64) {
				alignas(u64_t) static constexpr u8_t Config [64] = {
					0xf0, 0xef, 0xcb, 0xca, 0xbf, 0xd0, 0x04, 0x7b,
					0xc0, 0x5d, 0x3e, 0x3a, 0x1d, 0x53, 0xe4, 0x9f,
					0x07, 0xbf, 0x4f, 0xf5, 0xce, 0x67, 0x53, 0x53,
					0x9f, 0x0e, 0xf7, 0xfb, 0x22, 0xe6, 0xf4, 0xc3,
					0x74, 0xcc, 0xb9, 0xed, 0xc0, 0x50, 0x23, 0x81,
					0x65, 0x27, 0x7a, 0xc2, 0xb2, 0xea, 0xfb, 0x96,
					0xcb, 0x91, 0xe2, 0x97, 0x59, 0x94, 0x1f, 0x6d,
					0x51, 0xc3, 0x9f, 0xe5, 0x27, 0x31, 0xd1, 0xc5
				};
				std::memcpy( data->ubi_data.key_state,
					     Config,
					     sizeof(Config) );
				UBI_f::chain_message( &data->ubi_data,
						      TEMP_MEM.rng,
						      Skein_Bytes );
				UBI_f::chain_output( &data->ubi_data,
						     TEMP_MEM.rng,
						     RNG_Output_Size );
			} else {
				Skein_f::hash( &(data->ubi_data),// UBI Data
					       TEMP_MEM.rng,     // output
					       TEMP_MEM.rng,     // input
					       Skein_Bytes,      // input size
					       RNG_Output_Size );// output size
			}

			static constexpr int J1_Offset = Skein_Bytes;
			static constexpr int J2_Offset = J1_Offset + sizeof(u64_t);

			u64_t j1, j2;
			{
				std::memcpy( &j1, TEMP_MEM.rng + J1_Offset, sizeof(j1) );
				j1 >>= (64 - garlic);
				std::memcpy( &j2, TEMP_MEM.rng + J2_Offset, sizeof(j2) );
				j2 >>= (64 - garlic);
			}
			static_assert (sizeof(TEMP_MEM.word_buf) == (Skein_Bytes * 2));
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM.word_buf, 0),
					INDEX_HASH_WORD (GRAPH_MEM        ,j1));
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM.word_buf, 1),
					INDEX_HASH_WORD (GRAPH_MEM        ,j2));
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (GRAPH_MEM        ,j1),
					INDEX_HASH_WORD (TEMP_MEM.word_buf, 0));
		}
#undef GRAPH_MEM
#undef TEMP_MEM
	}// ~ void gamma_(Data*,u8_t const)
	TEMPLATE_ARGS void
	CLASS::phi_ (Data       *data,
		     u8_t const garlic)
	{
#define GRAPH_MEM data->graph_memory
#define TEMP_MEM  data->temp.phi
#define X_MEM     data->x_buffer
		u64_t const last_word_index = (static_cast<u64_t>(1) << garlic) - 1;
		int const   right_shift_amt = 64 - garlic;
		u64_t j;
		{
			std::memcpy( &j,
				     INDEX_HASH_WORD (GRAPH_MEM,last_word_index),
				     sizeof(j) );
			j >>= right_shift_amt;
		}
		COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,              0),
				INDEX_HASH_WORD (GRAPH_MEM,last_word_index));
		COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,1),
				INDEX_HASH_WORD (GRAPH_MEM,j));
		HASH_TWO_WORDS (data,
				INDEX_HASH_WORD (GRAPH_MEM,0),
				INDEX_HASH_WORD (TEMP_MEM ,0));
		for( u64_t i = 1; i <= last_word_index; ++i ) {
			{
				std::memcpy( &j,
					     INDEX_HASH_WORD (GRAPH_MEM,(i-1)),
					     sizeof(j) );
				j >>= right_shift_amt;
			}
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,   0 ),
					INDEX_HASH_WORD (GRAPH_MEM,(i-1)));
			COPY_HASH_WORD (INDEX_HASH_WORD (TEMP_MEM ,   1 ),
					INDEX_HASH_WORD (GRAPH_MEM,   j ));
			HASH_TWO_WORDS (data,
					INDEX_HASH_WORD (GRAPH_MEM,i),
					INDEX_HASH_WORD (TEMP_MEM ,0));
		}
		COPY_HASH_WORD (INDEX_HASH_WORD (X_MEM    ,0              ),
				INDEX_HASH_WORD (GRAPH_MEM,last_word_index));
	}// ~ void phi_(Data *,u8_t const)

}// ~ namespace ssc
#undef X_MEM
#undef GRAPH_MEM
#undef TEMP_MEM
#undef HASH_TWO_WORDS
#undef COPY_HASH_WORD
#undef INDEX_HASH_WORD
#undef CLASS
#undef TEMPLATE_ARGS
#undef DEFAULT_ARGS
