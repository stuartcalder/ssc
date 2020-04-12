#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/types.hh>
#include <ssc/general/error_conditions.hh>
/* SSC Crypto Headers */
#if 0
#include <ssc/crypto/skein.hh>
#else
#	include <ssc/crytpo/unique_block_iteration_f.hh>
#	include <ssc/crypto/skein_f.hh>
#endif
/* C Standard Headers */
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
/* C++ Standard Headers */
#include <new>
#include <limits>
#include <type_traits>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS	template <int      Skein_Bits,\
	                                  int      Salt_Bits,\
				          int      Max_Password_Bits,\
				          typename MHF_f,\
	                                  typename Gamma_f = Null_Type,\
				          typename Phi_f = Null_Type>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif

#ifndef CLASS
#	define CLASS	Catena_F<Skein_Bits,Salt_Bits,Max_Password_Bits,MHF_f,Gamma_f,Phi_f>
#else
#	error 'CLASS Already Defined'
#endif

namespace ssc
{
	TEMPLATE_ARGS
	class Catena_F
	{
	public:
		static_assert (CHAR_BIT == 8);
		static_assert (Skein_Bits == 256 || Skein_Bits == 512 || Skein_Bits == 1024);

		using UBI_f   = Unique_Block_Iteration_F<Skein_Bits>;
		using Skein_f = Skein_F<Skein_Bits>;
		static_assert (std::is_same<typename UBI_f::Data,typename Skein_f::Data_t>::value);
		using UBI_Data_t = typename UBI_f::Data_t;

		_CTIME_CONST (int)   Skein_Bytes  = Skein_Bits / CHAR_BIT;
		_CTIME_CONST (int)   Output_Bytes = Skein_Bytes;
		_CTIME_CONST (int)   Salt_Bytes   = Salt_Bits / CHAR_BIT;
		_CTIME_CONST (int)   Max_Password_Bytes = Max_Password_Bits / CHAR_BIT;
		//                                                                                   (represented in bytes)    (represented in bytes)
		//    Hash(Version String) -> Skein_Bytes || Domain -> 1 byte || lambda -> 1 byte || output size -> 2 bytes || salt size -> 2 bytes
		//                 Tweak Size =>   H(V) || d || lambda || m || |s|
		_CTIME_CONST (int)   Tweak_Bytes  = Skein_Bytes + 1 + 1 + 2 + 2;
		_CTIME_CONST (int)   Buffer_Bytes = Skein_Bytes + Tweak_Bytes + Max_Password_Bytes + Salt_Bytes;
		/* CONSTANTS DERIVED FROM TEMPLATE ARGUMENTS */
		_CTIME_CONST (auto&) Version_ID_Hash = MHF_f::Version_ID_Hash; // The version ID hash is supplied by the memory-hard function.
		static_assert (sizeof(Version_ID_Hash) == Skein_Bytes);

		enum class Domain_E : u8_t {
			Password_Scrambler = 0x00,
			Key_Derivation_Function = 0x01,
			Proof_Of_Work = 0x02
		};/* ~ enum class Domain_E:u8_t */
		
		Catena_F (void) = delete;

		static constexpr u64_t calculate_graph_buffer_size (u8_t const g_high);//TODO
		static void call (_RESTRICT (UBI_Data_t *) ubi_data,
				  _RESTRICT (u8_t *)       output,
				  _RESTRICT (u8_t *)       sensitive_buffer,
				  _RESTRICT (u8_t *)       password,
				  int const                password_size,
				  _RESTRICT (u8_t const *) salt,
				  u8_t const               g_low,
				  u8_t const               g_high,
				  u8_t const               lambda);
#if 0
		static void call (u8_t       *output,
				  Skein_t    *skein,
				  u8_t       *sensitive_buffer,
				  u8_t       *password,
				  int const  password_size,
				  u8_t const *salt,
				  u8_t const g_low,
				  u8_t const g_high,
				  u8_t const lambda);
#endif
	private:
		static inline void generate_tweak_ (u8_t *tweak, u8_t const lambda);
		static void flap_ (u8_t *in_out, u8_t *graph_memory, Skein_t *skein, u8_t const *salt, u8_t const garlic);
	};/* ~ class Catena_F<...> */

	TEMPLATE_ARGS
	constexpr u64_t calculate_graph_buffer_size (u8_t const g_high)
	{
		return (static_cast<u64_t>(1) << g_high) + 3;
	}

	TEMPLATE_ARGS
	void CLASS::generate_tweak_ (u8_t *tweak, u8_t const lambda)
	{
		u8_t *t = tweak;
		std::memcpy( t, Version_ID_Hash, sizeof(Version_ID_Hash) );
		t += sizeof(Version_ID_Hash);
		(*t) = static_cast<u8_t>(Domain_E::Key_Derivation_Function);
		++t;
		(*t) = lambda;
		++t;

		static_assert (Output_Bytes <= std::numeric_limits<u16_t>::max());
		static_assert (Salt_Bytes   <= std::numeric_limits<u16_t>::max());
		u16_t bytes = static_cast<u16_t>(Output_Bytes);
		std::memcpy( t, &bytes, sizeof(bytes) );
		t += sizeof(bytes);
		if constexpr(Output_Bytes != Salt_Bytes)
			bytes = static_cast<u16_t>(Salt_Bytes);
		std::memcpy( t &bytes, sizeof(bytes) );
	}

	TEMPLATE_ARGS
	void CLASS::flap_ (u8_t *in_out, u8_t *graph_memory, Skein_t *skein, u8_t const *salt, u8_t const garlic)
	{
		/* Initialize the memory */
		using std::memcpy;
		/* [Skein_Bytes * 2][Skein_Bytes][Skein_Bytes]
		 * [op_buffer      ][v_-2       ][v_-1       ]
		 */

		u8_t *op_buffer = graph_memory;

		u8_t *graph = op_buffer + (Skein_Bytes * 2); // Here, graph points to v_-2
		skein->hash( graph, in_out, Skein_Bytes, (Skein_Bytes * 2) ); // v_-2 and v_-1 are now filled. graph still points to v_-2.

		u64_t const last_index = ((static_cast<u64_t>(1) << garlic) - 1);
		for (u64_t i = 0; i <= last_index; ++i) {
			memcpy( op_buffer, (graph + Skein_Bytes), Skein_Bytes );
			memcpy( (op_buffer + Skein_Bytes), graph, Skein_Bytes );
			graph += (Skein_Bytes * 2);
			skein->hash_native( graph, op_buffer, (Skein_Bytes * 2) );
		}
		/* TODO Run the Gamma function, if it exists. */
		if constexpr(!std::is_same<Gamma_f,Null_Type>::value) {
			//TODO Gamma function, that modifies the graph memory based on a public input.
		}
		/* TODO Run the Memory-Hard Lambda function. */
		{
		}
		/* TODO Run the Phi function, if it exists. */
		if constexpr(!std::is_same<Phi_f,Null_Type>::value) {
			//TODO Phi function, that modifies the graph memory based on a secret input.
		}
	}

	TEMPLATE_ARGS
	void CLASS::call (_RESTRICT (UBI_Data_t *) ubi_data,
		          _RESTRICT (u8_t *)       output,
		          _RESTRICT (u8_t *)       sensitive_buffer,
		          _RESTRICT (u8_t *)       password,
		          int const                password_size,
		          _RESTRICT (u8_t const *) salt,
		          u8_t const               g_low,
		          u8_t const               g_high,
		          u8_t const               lambda)
	{
#ifndef __SSC_DISABLE_RUNTIME_CHECKS
		// Check to see that the inputs are valid.
		if( (g_high > 63) || (g_low > g_high) || (g_low == 0) || (lambda == 0) )
			errx( "ERROR: One or more invalid inputs to Catena_F was invalid!\n" );
#endif /* ~ #ifndef __SSC_DISABLE_RUNTIME_CHECKS */
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
#undef CLASS
#undef TEMPLATE_ARGS
