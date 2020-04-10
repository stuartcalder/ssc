#pragma once
#include <ssc/crypto/skein_f.hh>

#if    defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'Some MACRO we need was already defined'
#endif

#define TEMPLATE_ARGS	template <int Bits>
#define CLASS		Skein_CSPRNG_F<Bits,Max_Bits>

namespace ssc
{
	TEMPLATE_ARGS
	class Skein_CSPRNG_F
	{
	public:
		static_assert (CHAR_BIT == 8);
		static_assert (Bits == 256 || Bits == 512 || Bits == 1024);
		using Skein_f = Skein_F<Bits>;
		using Data_t  = typename Skein_f::Data_t;
		_CTIME_CONST (int) State_Bits = Bits;
		_CTIME_CONST (int) State_Bytes = State_Bits / CHAR_BIT;

		struct Data {
			typename Skein_f::Data_t skein_data;
			alignas(u64_t)      u8_t buffer [State_Bytes * 2];
			alignas(u64_t)      u8_t seed   [State_Bytes];
		};

		static inline void initialize_seed (Data *data);
		static void        reseed          (Data *__restrict data, u8_t const *__restrict seed);
		static void        os_reseed       (Data *data);
		static void        get             (Data *__restrict data, u8_t const *__restrict output, u64_t requested_bytes);
	};

	TEMPLATE_ARGS
	void CLASS:initialize_seed (Data *data)
	{
		obtain_os_entropy( data->seed, sizeof(data->seed) );
	}
	TEMPLATE_ARGS
	void CLASS::reseed (Data *__restrict data, u8_t const *__restrict seed)
	{
		std::memcpy( data->buffer              , data->seed, State_Bytes );
		std::memcpy( data->buffer + State_Bytes, seed      , State_Bytes );
		static_assert (Skein_f::State_Bytes == State_Bytes);
		Skein_f::hash_native( &(data->skein_data), data->seed, data->buffer, sizeof(data->buffer) );
		zero_sensitive( data->buffer, sizeof(data->buffer) );
	}
	TEMPLATE_ARGS
	void CLASS::os_reseed (Data *data)
	{
		std::memcpy( data->buffer, data->seed, State_Bytes );
		obtain_os_entropy( (data->buffer + State_Bytes), State_Bytes );
		Skein_f::hash_native( &(data->skein_data), data->seed, data->buffer, sizeof(data->buffer) );
		zero_sensitive( data->buffer, sizeof(data->buffer) );
	}
	TEMPLATE_ARGS
	void CLASS::get (Data *__restrict data, u8_t const *__restrict output, u64_t requested_bytes)
	{
		while( requested_bytes > State_Bytes ) {
			Skein_f::hash( &(data->skein_data), data->buffer, data->seed, sizeof(data->seed), sizeof(data->buffer) );
			std::memcpy( data->seed, data->buffer                , State_Bytes );
			std::memcpy( output    , (data->buffer + State_Bytes), State_Bytes );
			requested_bytes -= State_Bytes;
		}
		Skein_f::hash( &(data->skein_data), data->buffer, data->seed, sizeof(data->seed), sizeof(data->buffer) );
		std::memcpy( data->seed, data->buffer                , State_Bytes );
		std::memcpy( output    , (data->buffer + State_Bytes), requested_bytes );
	}
}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
