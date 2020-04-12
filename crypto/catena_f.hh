#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/types.hh>
#include <ssc/general/error_conditions.hh>
/* SSC Crypto Headers */
#include <ssc/crytpo/unique_block_iteration_f.hh>
#include <ssc/crypto/skein_f.hh>
#endif
/* C Standard Headers */
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
/* C++ Standard Headers */
#include <limits>
#include <type_traits>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS	template <int      Skein_Bits,\
	                                  int      Salt_Bits,\
				          int      Max_Password_Bits,\
				          typename MHF_f,\
	                                  typename Gamma_f = void,\
				          typename Phi_f   = void>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif

#ifndef CLASS
#	define CLASS	Catena_F<Skein_Bits,Salt_Bits,Max_Password_Bits,MHF_f,Gamma_f,Phi_f>
#else
#	error 'CLASS Already Defined'
#endif

#if    defined (INDEX_HASH_WORD) || defined (COPY_HASH_WORD) || \
       defined (HASH_TWO_WORDS)  || defined (GRAPH_MEM)      || defined (TEMP_MEM)
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
		using Lambda_t   = u8_t; // Lambda represents a cost of time.
		using Garlic_t   = u8_t; // Garlic represents a cost of memory.

		_CTIME_CONST (int)   Skein_Bytes  = Skein_Bits / CHAR_BIT;
		_CTIME_CONST (int)   Output_Bytes = Skein_Bytes;
		_CTIME_CONST (int)   Salt_Bytes   = Salt_Bits / CHAR_BIT;
		_CTIME_CONST (int)   Max_Password_Bytes = Max_Password_Bits / CHAR_BIT;
		//                                                                                   (represented in bytes)    (represented in bytes)
		//    Hash(Version String) -> Skein_Bytes || Domain -> 1 byte || lambda -> 1 byte || output size -> 2 bytes || salt size -> 2 bytes
		//                 Tweak Size =>   H(V) || d || lambda || m || |s|
		_CTIME_CONST (int)   Tweak_Bytes  = Skein_Bytes + 1 + 1 + 2 + 2;
		/* CONSTANTS DERIVED FROM TEMPLATE ARGUMENTS */
		_CTIME_CONST (auto&) Version_ID_Hash = MHF_f::Version_ID_Hash; // The version ID hash is supplied by the memory-hard function.
		static_assert (sizeof(Version_ID_Hash) == Skein_Bytes);

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
				u8_t                tw_pw_slt [Tweak_Bytes + Max_Password_Bytes + Salt_Bytes];
				alignas(u64_t) u8_t flap      [Skein_Bytes * 3];
				u8_t                catena    [Skein_Bytes + sizeof(Garlic_t)];
			} temp;
		};

		static inline u64_t calculate_graph_buffer_size (Garlic_t const g_high);
		static void call (_RESTRICT (Data *) data,
				  _RESTRICT (u8_t *) output,
				  _RESTRICT (u8_t *) password,
				  int const          password_size,
				  Garlic_t const     g_low,
				  Garlic_t const     g_high,
				  Lambda_t const     lambda);
	private:
		static inline void make_tweak_ (Data *data, Lambda_t const lambda);
		static void flap_ (Data *data,
				   Garlic_t const garlic,
				   Lambda_t const lambda);
#if 0
		static void flap_ (u8_t *in_out, u8_t *graph_memory, Skein_t *skein, u8_t const *salt, u8_t const garlic);
#endif
	};/* ~ class Catena_F<...> */

	TEMPLATE_ARGS
	u64_t CLASS::calculate_graph_buffer_size (Garlic_t const g_high)
	{
		return (static_cast<u64_t>(1) << g_high) + 3;
	}

	TEMPLATE_ARGS
	void CLASS::make_tweak_ (Data *data, Lambda_t const lambda)
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
			   Garlic_t const garlic,
			   Lambda_t const lambda)
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
		COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,1),
				INDEX_HASH_WORD (TEMP_MEM,0));
		COPY_HASH_WORD (INDEX_HASH_WORD (GRAPH_MEM,0),
				INDEX_HASH_WORD (TEMP_MEM,1));
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
		// Gamma function call.
		if constexpr (!std::is_same<Gamma_f,void>::value) {
			Gamma_f::call( data->graph_memory,
				       data->salt,
				       garlic );
		}
		{// Memory-Hard function call.
			MHF_f::call( data->graph_memory, lambda );
		}
		// Phi function call.
		if constexpr (!std::is_same<Phi_f,void>::value) {
			/*TODO Phi function */
		} else {
			std::memcpy( data->x_buffer,
				     INDEX_HASH_WORD (GRAPH_MEM,max_hash_index),
				     Skein_Bytes );
		}
		/*TODO Write to the X buffer */
	}

	TEMPLATE_ARGS
	void CLASS::call (_RESTRICT (Data *) data,
	 	          _RESTRICT (u8_t *) output,
		          _RESTRICT (u8_t *) password,
		          int const          password_size,
		          Garlic_t const     g_low,
		          Garlic_t const     g_high,
		          Lambda_t const     lambda)
	{
#ifndef __SSC_DISABLE_RUNTIME_CHECKS
		// Check to see that the inputs are valid.
		if( (g_high > 63) || (g_low > g_high) || (g_low == 0) || (lambda == 0) )
			errx( "ERROR: One or more invalid inputs to Catena_F was invalid!\n" );
#endif /* ~ #ifndef __SSC_DISABLE_RUNTIME_CHECKS */
	}
	TEMPLATE_ARGS
	void CLASS::call (_RESTRICT (Data *)       data,
		          _RESTRICT (u8_t *)       output,
		          _RESTRICT (u8_t *)       password,
		          int const                password_size,
		          Garlic_t const           g_low,
		          Garlic_t const           g_high,
		          Lambda_t const           lambda)
	{
#ifndef __SSC_DISABLE_RUNTIME_CHECKS
		// Check to see that the inputs are valid.
		if( (g_high > 63) || (g_low > g_high) || (g_low == 0) || (lambda == 0) )
			errx( "ERROR: One or more invalid inputs to Catena_F was invalid!\n" );
#endif /* ~ #ifndef __SSC_DISABLE_RUNTIME_CHECKS */
		u64_t const graph_memory_size = calculate_graph_buffer_size( g_high );
		data->graph_memory = static_cast<u8_t*>(std::malloc( graph_memory_size ));
		if( data->graph_memory == nullptr ) {
			zero_sensitive( password, password_size );
			errx( "Error: Catena failed to malloc... Memory requirement too high?\n" );
		}
		// Generate the tweak.
		{
			make_tweak_( data, lambda );
		}
		// Append the password and salt to the end of the tweak.
		{
			u8_t *p = data->temp.tw_pw_slt + Tweak_Bytes;
			std::memcpy( p, password, password_size );
			p += password_size;
			std::memcpy( p, data->salt, Salt_Bytes );
		}
		// Hash the concatenated (tweak|password|salt), outputting into the x buffer.
		{
			Skein_f::hash_native( &(data->ubi_data),
				              data->x_buffer,
				              data->temp.tw_pw_slt,
				              (password_size + (Tweak_Bytes + Salt_Bytes)) );
		}
		// Initial flap.
		flap_( data, ((g_low + 1) / 2) );
		// Hash x_buffer into itself.
		Skein_f::hash_native( &(data->ubi_data),
				      data->x_buffer,
				      data->x_buffer,
				      Skein_Bytes );
		// Begin flapping.
		for( Garlic_t g = g_low; g <= g_high; ++g ) {
			flap_( data, g );
			(*(reinterpret_cast<Garlic_t*>(data->temp.catena))) = g;
			std::memcpy( (data->temp.catena + sizeof(Garlic_t)),
				     data->x_buffer,
				     Skein_Bytes );
			Skein_f::hash_native( &(data->ubi_data),
					      data->x_buffer,
					      data->temp.catena
					      sizeof(data->temp.catena) );
		}
		{
			zero_sensitive( graph_memory, graph_memory_size );
			std::free( graph_memory );
		}
		std::memcpy( output,
			     data->x_buffer,
			     Skein_Bytes );
	}
	TEMPLATE_ARGS
	void CLASS::call (u8_t       *output,
			  Skein_t    *skein,
			  u8_t       *sensitive_buffer,
			  u8_t       *password,
			  int const  password_size,
			  u8_t const *salt,
			  u8_t const g_low,
			  u8_t const g_high,
			  u8_t const lambda)
	{
#ifndef __SSC_DISABLE_RUNTIME_CHECKS
		// Check to see that the inputs are valid.
		{
			if ((g_high > 63) || (g_low > g_high) || (g_low == 0) || (lambda == 0 ))
				errx( "ERROR: One or more invalid inputs to Catena_F was invalid!\n" );
		}
#endif /* ~ #ifndef __SSC_DISABLE_RUNTIME_CHECKS */

		/* sensitive_buffer layout:
		 * [Primary_Buf][Tweak_Buf  ][Password_Buf      ][Salt_Buf  ] <--- Name
		 * [Skein_Bytes][Tweak_Bytes][Max_Password_Bytes][Salt_Bytes] <--- Size
		 */
		_CTIME_CONST (int) Tweak_Offset = Skein_Bytes;
		_CTIME_CONST (int) Password_Offset = Tweak_Offset + Tweak_Bytes;
		_CTIME_CONST (int) Salt_Offset = Password_Offset + Max_Password_Bytes;
		u8_t *sensitive_ptr = sensitive_buffer + Tweak_Offset;
		_CTIME_CONST (int) Max_Sensitive_Bytes = Tweak_Bytes + Max_Password_Bytes + Salt_Bytes;

		// Claim the massive amounts of memory we're going to soon need.
		u64_t const graph_buffer_size = calculate_graph_buffer_size( g_high );//TODO
		u8_t *graph_buffer = new (std::nothrow) u8_t [graph_buffer_size];
		if (graph_buffer == nullptr) {
			zero_sensitive( sensitive_ptr, Max_Sensitive_Bytes );
			zero_sensitive( password, password_size );
			errx( "ERROR: Failed to allocate memory in Catena_F... Was the memory cost parameter too high?\n" );
		}

		// Generate the tweak.
		{
			generate_tweak_( sensitive_ptr, lambda );
		}
		// Append the password and salt to the end of the tweak.
		{
			u8_t *p = sensitive_ptr + Tweak_Bytes;
			std::memcpy( p, password, password_size );
			p += password_size;
			std::memcpy( p, salt, Salt_Bytes );
		}
		// Hash the concatenated (tweak|password|salt), outputting into the x buffer.
		{
			int const sensitive_bytes = password_size + (Tweak_Bytes + Salt_Bytes);
			skein->hash_native( sensitive_buffer, sensitive_ptr, sensitive_bytes );
		}
		// Zero over the sensitive data.
		{
			zero_sensitive( sensitive_ptr, Max_Sensitive_Bytes );
			zero_sensitive( password, password_size );
		}
		// Do an initial call to flap with g_low, the x buffer, and the "public input".
		{
			//TODO
		}
		// Hash the x buffer, outputting back into itself.
		// TODO
		// TODO Intermediate Shit
		// Zero over the graph memory and free it.
		{
			zero_sensitive( graph_buffer, graph_buffer_size );
			delete[] graph_buffer;
		}
	}/* ~ void call(...) */
}/* ~ namespace ssc */
#undef GRAPH_MEM
#undef TEMP_MEM
#undef HASH_TWO_WORDS
#undef COPY_HASH_WORD
#undef INDEX_HASH_WORD
#undef CLASS
#undef TEMPLATE_ARGS
