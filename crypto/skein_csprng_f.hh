/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#include <shim/operations.h>
#include <ssc/crypto/skein_f.hh>

#if    defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'Some MACRO we need was already defined'
#endif

#define TEMPLATE_ARGS	template <int Bits>
#define CLASS		Skein_CSPRNG_F<Bits>

namespace ssc
{
	TEMPLATE_ARGS class
	Skein_CSPRNG_F
	{
	public:
		static_assert (CHAR_BIT == 8,
			       "Bytes must be 8-bits.");
		static_assert (Bits == 256 || Bits == 512 || Bits == 1024,
			       "Skein only specified for 256,512,1024 bits.");
		using Skein_f = Skein_F<Bits>;
		enum Int_Constants : int {
			State_Bits = Bits,
			State_Bytes = State_Bits / CHAR_BIT
		};

		struct Data {
			typename Skein_f::Data_t       skein_data;
			alignas(uint64_t)      uint8_t buffer [State_Bytes * 2];
			alignas(uint64_t)      uint8_t seed   [State_Bytes];
		};

		static inline void
		initialize_seed (Data *data);

		static void
		reseed (Data *          SHIM_RESTRICT data,
			uint8_t const * SHIM_RESTRICT seed);

		static void
		os_reseed (Data *data);

		static void
		get (Data *    SHIM_RESTRICT data,
		     uint8_t * SHIM_RESTRICT output,
		     uint64_t                requested_bytes);
	};

	TEMPLATE_ARGS void
	CLASS::initialize_seed (Data *data)
	{
		shim_obtain_os_entropy( data->seed, sizeof(data->seed) );
	}

	TEMPLATE_ARGS void
	CLASS::reseed (Data *          SHIM_RESTRICT data,
		       uint8_t const * SHIM_RESTRICT seed)
	{
		std::memcpy( data->buffer              , data->seed, State_Bytes );	// Copy the whole stored seed into the stored temporary buffer.
		std::memcpy( data->buffer + State_Bytes, seed      , State_Bytes );	// Copy the whole new    seed into the stored temporary buffer.
		static_assert (Skein_f::State_Bytes == State_Bytes);
		Skein_f::hash_native( &data->skein_data,	// UBI data
				      data->seed,		// Output into the stored seed buffer.
				      data->buffer,		// Input from the stored temporary buffer.
				      sizeof(data->buffer) );	// Input the entire stored temporary buffer.
		shim_secure_zero( data->buffer, sizeof(data->buffer) );
	}

	TEMPLATE_ARGS void
	CLASS::os_reseed (Data *data)
	{
		std::memcpy( data->buffer, data->seed, State_Bytes );		// Copy the whole stored seed into the stored temporary buffer.
		shim_obtain_os_entropy( data->buffer + State_Bytes, State_Bytes );
		Skein_f::hash_native( &data->skein_data,	// UBI data
				      data->seed,		// Output into the stored seed buffer.
				      data->buffer,		// Input from the stored temporary buffer.
				      sizeof(data->buffer) );	// Input the entire stored temporary buffer.
		shim_secure_zero( data->buffer, sizeof(data->buffer) );
	}

	TEMPLATE_ARGS void
	CLASS::get (Data *    SHIM_RESTRICT data,
		    uint8_t * SHIM_RESTRICT output,
		    uint64_t                requested_bytes)
	{
		while( requested_bytes > State_Bytes ) { // Until we have less than a block left...
			Skein_f::hash( &data->skein_data,	// UBI Data
				       data->buffer,		// Output into the stored temporary buffer.
				       data->seed,		// Input from the stored seed buffer.
				       sizeof(data->seed),	// Input the entire stored seed buffer.
				       sizeof(data->buffer) );	// Output into the entire stored temporary buffer.
			std::memcpy( data->seed, data->buffer                , State_Bytes ); // Copy 1st $State_Bytes of stored temporary buffer into the stored seed buffer.
			std::memcpy( output    , (data->buffer + State_Bytes), State_Bytes ); // Copy 2nd $State_Bytes of stored temporary buffer out of the function.
			output          += State_Bytes;	// Increment the output pointer by one block.
			requested_bytes -= State_Bytes;	// Decrement the counter by one block.
		}
		Skein_f::hash( &data->skein_data,	// UBI Data
			       data->buffer,		// Output into the stored temporary buffer.
			       data->seed,		// Input from the stored seed buffer.
			       sizeof(data->seed),	// Input the entire stored seed buffer.
			       sizeof(data->buffer) );	// Output into the entire stored temporary buffer.
		// Copy the 1st $State_Bytes bytes of data->buffer as the first $State_Bytes bytes of data->seed.
		std::memcpy( data->seed,
			     data->buffer,
			     State_Bytes );
		// Copy the remaining $requested_bytes bytes of data->buffer out of the function.
		std::memcpy( output,
			     (data->buffer + State_Bytes),
			     requested_bytes );
	}
}// ~ namespace ssc
#undef CLASS
#undef TEMPLATE_ARGS
