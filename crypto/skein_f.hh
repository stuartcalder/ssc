/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#include <ssc/crypto/unique_block_iteration_f.hh>

#if    defined (DEFAULT_ARGS) || defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'Some MACRO we need was already defined'
#endif

#define DEFAULT_ARGS	template <int Bits, Key_Schedule_E Tf_Key_Sch = Key_Schedule_E::On_Demand>
#define TEMPLATE_ARGS	template <int Bits, Key_Schedule_E Tf_Key_Sch>
#define CLASS		Skein_F<Bits,Tf_Key_Sch>

namespace ssc
{
	DEFAULT_ARGS class
	Skein_F
	{
	public:
		using UBI_f = Unique_Block_Iteration_F<Bits,Tf_Key_Sch>;
		using Data_t = typename UBI_f::Data;

		static_assert (CHAR_BIT == 8);
		enum Int_Constants : int {
			State_Bits = Bits,
			State_Bytes = State_Bits / CHAR_BIT
		};

		Skein_F (void) = delete;

		/* Generic hashing. Hash the input bytes and output $num_bytes_out bytes into $bytes_out.
		 */
		static void
		hash (Data_t * SHIM_RESTRICT ubi_data,
		      uint8_t *              bytes_out,
		      uint8_t *              bytes_in,
		      uint64_t const         num_bytes_in,
		      uint64_t const         num_bytes_out);
		
		/* Native hashing. Hash the input bytes and output $State_Bytes bytes into $bytes_out.
		 */
		static void 
		hash_native (Data_t * SHIM_RESTRICT ubi_data,
			     uint8_t *              bytes_out,
			     uint8_t const *        bytes_in,
			     uint64_t const         num_bytes_in);

		/* Message Auth Code hashing. Hash the input bytes and the key and output $State_Bytes bytes into $bytes_out.
		 */
		static void
		mac (Data_t *        SHIM_RESTRICT ubi_data,
		     uint8_t *                     bytes_out,
		     uint8_t const *               bytes_in,
		     uint8_t const * SHIM_RESTRICT key_in,
		     uint64_t const                num_bytes_out,
		     uint64_t const                num_bytes_in);
				         
	};

	TEMPLATE_ARGS void
	CLASS::hash (Data_t * SHIM_RESTRICT ubi_data,
		     uint8_t *              bytes_out,
		     uint8_t *              bytes_in,
		     uint64_t const         num_bytes_in,
		     uint64_t const         num_bytes_out)
	{
		std::memset( ubi_data->key_state, 0, State_Bytes );		// Zero over $State_Bytes bytes of UBI's key state.
		UBI_f::chain_config( ubi_data, (num_bytes_out * CHAR_BIT) );	// Process the configuration string with the requested output size.
		UBI_f::chain_message( ubi_data, bytes_in, num_bytes_in );	// Process the message into UBI's state.
		UBI_f::chain_output( ubi_data, bytes_out, num_bytes_out );	// Chain the output out of the function.
	}

	TEMPLATE_ARGS void
	CLASS::hash_native (Data_t * SHIM_RESTRICT ubi_data,
		            uint8_t *              bytes_out,
		            uint8_t const *        bytes_in,
		            uint64_t const         num_bytes_in)
	{
		static_assert (State_Bits == 256 || State_Bits == 512 || State_Bits == 1024);
		// Copy initial pre-computed chaining value into UBI's key state.
		if constexpr (State_Bits == 256) {
			static constexpr uint64_t init [4] = {
				0xfc'9d'a8'60'd0'48'b4'49,
                                0x2f'ca'66'47'9f'a7'd8'33,
                                0xb3'3b'c3'89'66'56'84'0f,
                                0x6a'54'e9'20'fd'e8'da'69
			};
			std::memcpy( ubi_data->key_state, init, sizeof(init) );
		} else if constexpr (State_Bits == 512) {
			static constexpr uint64_t init [8] = {
				0x49'03'ad'ff'74'9c'51'ce,
                                0x0d'95'de'39'97'46'df'03,
                                0x8f'd1'93'41'27'c7'9b'ce,
                                0x9a'25'56'29'ff'35'2c'b1,
                                0x5d'b6'25'99'df'6c'a7'b0,
                                0xea'be'39'4c'a9'd5'c3'f4,
                                0x99'11'12'c7'1a'75'b5'23,
                                0xae'18'a4'0b'66'0f'cc'33
			};
			std::memcpy( ubi_data->key_state, init, sizeof(init) );
		} else if constexpr (State_Bits == 1024) {
			static constexpr uint64_t init [16] = {
				0xd5'93'da'07'41'e7'23'55, // 0
                                0x15'b5'e5'11'ac'73'e0'0c, // 1
                                0x51'80'e5'ae'ba'f2'c4'f0, // 2
                                0x03'bd'41'd3'fc'bc'af'af, // 3
                                0x1c'ae'c6'fd'19'83'a8'98, // 4
                                0x6e'51'0b'8b'cd'd0'58'9f, // 5
                                0x77'e2'bd'fd'c6'39'4a'da, // 6
                                0xc1'1e'1d'b5'24'dc'b0'a3, // 7
                                0xd6'd1'4a'f9'c6'32'9a'b5, // 8
                                0x6a'9b'0b'fc'6e'b6'7e'0d, // 9
                                0x92'43'c6'0d'cc'ff'13'32, //10
                                0x1a'1f'1d'de'74'3f'02'd4, //11
                                0x09'96'75'3c'10'ed'0b'b8, //12
                                0x65'72'dd'22'f2'b4'96'9a, //13
                                0x61'fd'30'62'd0'0a'57'9a, //14
                                0x1d'e0'53'6e'86'82'e5'39
			};
			std::memcpy( ubi_data->key_state, init, sizeof(init) );
		}
		// Process the message into UBI's state.
		UBI_f::chain_message( ubi_data, bytes_in, num_bytes_in );
		// Process the output, outputting outside the function.
		UBI_f::chain_native_output( ubi_data, bytes_out );
	}

	TEMPLATE_ARGS void
	CLASS::mac (Data_t *        SHIM_RESTRICT ubi_data,
		    uint8_t *                     bytes_out,
		    uint8_t const *               bytes_in,
		    uint8_t const * SHIM_RESTRICT key_in,
		    uint64_t const                num_bytes_out,
		    uint64_t const                num_bytes_in)
	{
		// We chain a key type value.
		using T_Mask_e = typename UBI_f::Type_Mask_E;

		// Zero over UBI's key state.
		std::memset( ubi_data->key_state, 0, State_Bytes );
		// Chain the key into UBI's key state.
		UBI_f::template chain_type<T_Mask_e::Key,State_Bytes>( ubi_data, key_in );
		// Process the configuration string, given the number of output bytes requested.
		UBI_f::chain_config( ubi_data, (num_bytes_out * CHAR_BIT) );
		// Process the message into UBI's key state.
		UBI_f::chain_message( ubi_data, bytes_in, num_bytes_in );
		// Chain the output outside the function.
		UBI_f::chain_output( ubi_data, bytes_out, num_bytes_out );
	}
}// ~ namespace ssc
                                
#undef CLASS
#undef TEMPLATE_ARGS
#undef DEFAULT_ARGS
