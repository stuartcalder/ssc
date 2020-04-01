#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/types.hh>
#include <ssc/general/error_conditions.hh>
/* SSC Crypto Headers */
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/crypto/skein.hh>
/* C Standard Headers */
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
/* C++ Standard Headers */
#include <memory>
#include <type_traits>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS template <int      Skein_Bits,\
	                               typename Gamma_f,\
				       typename MHF_f,\
				       typename Phi_f = Null_Type>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif

#ifndef CLASS
#	define CLASS Catena_F<Skein_Bits,Gamma_f,MHF_f,Phi_f>
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

		using Threefish_t = Threefish<Skein_Bits>;
		using UBI_t = Unique_Block_Iteration<Threefish_t,Skein_Bits>;
		using Skein_t = Skein<Skein_Bits>;

		_CTIME_CONST(int)   Skein_Bytes  = Skein_Bits / CHAR_BIT;
		_CTIME_CONST(int)   Output_Bytes = Skein_Bytes;
		//    Hash(Version String) -> Skein_Bytes || Domain -> 1 byte || lambda -> 1 byte || output size -> 1 byte || salt size -> 1 byte
		//                 Tweak Size =>   H(V) || d || lambda || m || |s|
		_CTIME_CONST(int)   Tweak_Bytes  = Skein_Bytes + 1 + 1 + 1 + 1;
		_CTIME_CONST(auto&) Version_ID   = "Dragonfly-Full-V1";

		enum class Domain_E {
			Password_Scrambler = 0x00,
			Key_Derivation_Function = 0x01,
			Proof_Of_Work = 0x02
		};
		
		Catena_F (void) = delete;

		constexpr int calculate_buffer_size (int pw_size, int slt_size);

		static void call (u8_t       *output,
				  Skein_t    *skein,
				  u8_t       *crypto_buf,
				  int const  crypto_buf_size,
				  u8_t       *password,
				  int const  password_size,
				  u8_t const *salt,
				  u8_t const salt_size,
				  u8_t const g_low,
				  u8_t const g_high,
				  u8_t const lambda);
	private:
		static void flap_ (/*TODO*/);
	};

	TEMPLATE_ARGS
	constexpr int CLASS::calculate_buffer_size (int pw_size, int tw_size, int slt_size)
	{
		return Skein_Bytes +
		//TODO
	}/* ~ constexpr int calculate_buffer_size (int pw_size,int tw_size,int slt_size) */

	TEMPLATE_ARGS
	void CLASS::call (u8_t       *output,
			  Skein_t    *skein,
			  u8_t       *crypto_buf,
			  int const  crypto_buf_size,
			  u8_t       *password,
			  int const  password_size,
			  u8_t const *salt,
			  u8_t const salt_size,
			  u8_t const g_low,
			  u8_t const g_high,
			  u8_t const lambda)
	{
#ifndef __SSC_DISABLE_RUNTIME_CHECKS
		if ((g_high > 64) || (g_low > g_high) || (lambda == 0) || (g_low == 0))
			errx( "One or more invalid inputs to Catena_F\n" );
#endif /* ~ #ifndef __SSC_DISABLE_RUNTIME_CHECKS */
		// Setup the tweak.
	}/* ~ void call(...) */

}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
