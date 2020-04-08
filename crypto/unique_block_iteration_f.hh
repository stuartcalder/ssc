#pragma once

#include <cstdio>
#include <cstdlib>
#include <ssc/crypto/constants.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish_f.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>

#if    defined (DEFAULT_ARGS) || defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'DEFAULT_ARGS, TEMPLATE_ARGS or CLASS already defined'
#endif
#define DEFAULT_ARGS	template <int Bits, Key_Schedule_E Threefish_KS = Key_Schedule_E::Runtime_Compute>
#define TEMPLATE_ARGS	template <int Bits, Key_Schedule_E Threefish_KS>
#define CLASS		Unique_Block_Iteration_F<Bits,Threefish_KS>

namespace ssc
{
	DEFAULT_ARGS
	class Unique_Block_Iteration_F
	{
	public:
	/* Compile-Time checks, Constatns, and Aliases */
		static_assert (CHAR_BIT == 8);
		static_assert (Bits % 8 == 0);
		using Threefish_f = Threefish_F<Bits,Threefish_KS>;

		_CTIME_CONST (int) State_Bits = Bits;
		_CTIME_CONST (int) State_Bytes = State_Bits / CHAR_BIT;
		_CTIME_CONST (int) Tweak_Bits = Threefish_f::Tweak_Bits;
		_CTIME_CONST (int) Tweak_Bytes = Tweak_Bits / CHAR_BIT;

		enum class Type_Mask_E : u8_t {
			Key =  0,
			Cfg =  4,
			Prs =  8,
			Pk  = 12,
			Kdf = 16,
			Non = 20,
			Msg = 48,
			Out = 63
		};
		_CTIME_CONST (u8_t) Tweak_First_Bit  = 0b0100'0000;
		_CTIME_CONST (u8_t) Tweak_First_Mask = ~(Tweak_First_Bit);
		_CTIME_CONST (u8_t) Tweak_Last_Bit   = 0b1000'0000;
		_CTIME_CONST (u8_t) Tweak_Last_Mask  = ~(Tweak_Last_Bit);

		struct Data {
			Threefish_f::Data_t threefish_data;
			u64_t               key_state   [Threefish_f::External_Key_Words];
			alignas(u64_t) u8_t msg_state   [Threefish_f::Block_Bytes];
			u64_t               tweak_state [Threefish_f::External_Tweak_Words];
		};

		static void chain_config (Data *data, u64_t const num_out_bits);
		static void chain_native_output (Data *__restrict data, u8_t *__restrict output, u64_t const num_out_bytes);
		static void chain_message (Data *__restrict data, u8_t const *__restrict input, u64_t num_in_bytes);
		static void chain_output (Data *__restrict data, u8_t *__restrict output, u64_t num_out_bytes);
	/* Constructors / Destructors */
	};/* ~ class Unique_Block_Iteration_F */

	TEMPLATE_ARGS
	void CLASS::chain_config (Data *data, u64_t const num_out_bits)
	{
		// Zero the tweak.
		std::memset( data->tweak_state, 0, Tweak_Bytes );
		_CTIME_CONST (u8_t) Initial_Bitwise_Or = (Tweak_First_Bit | Tweak_Last_Bit | static_cast<u8_t>(Type_Mask_E::Cfg));
		// Set the first bit of the tweak, and the type.
		reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] |= Initial_Bitwise_Or;
		// Set the "position" of the tweak.
		data->tweak_state[ 0 ] = static_cast<u64_t>(32);

		_CTIME_CONST (u8_t) config [32] = {
			// First 4 bytes
			0x53, 0x48, 0x41, 0x33, // Schema identifier "SHA3"
			// Next 2 bytes
			0x01, 0x00, // Version number (1)
			// Next 2 bytes
			0x00, 0x00, // Reserved (0)
			// Next 8 bytes
			0x00, 0x00, 0x00, 0x00, // Output length
			0x00, 0x00, 0x00, 0x00,
			// Remaining 16 bytes
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};

		// Copy the config into the msg_state.
		static_assert (sizeof(data->msg_state) >= sizeof(config),
				"With this implementation, it must be possible to process the config string with one block.");

		std::memcpy( data->msg_state, config, sizeof(config) );
		*(reinterpret_cast<u64_t*>(data->msg_state + 8)) = num_out_bits;
		// Zero pad the msg_state if the message block is larger than the configuration string.
		if constexpr (sizeof(config) < sizeof(data->msg_state))
			std::memset( (data->msg_state + sizeof(config)), 0, (sizeof(data->msg_state) - sizeof(config)) );
		Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
		Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
		xor_block<State_Bits>( data->key_state, data->msg_state );
	}

	TEMPLATE_ARGS
	void CLASS::chain_native_output (Data *__restrict data, u8_t *__restrict output, u64_t const num_out_bytes)
	{
		std::memset( data->tweak_state, 0, Tweak_Bytes );
		_CTIME_CONST (u8_t) Initial_Bitwise_Or = (Tweak_First_Bit | Tweak_Last_Bit | static_cast<u8_t>(Type_Mask_E::Out));
		reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] |= Initial_Bitwise_Or;
		data->tweak_state[ 0 ] = static_cast<u64_t>(Block_Bytes);
		std::memset( data->msg_state, 0, sizeof(data->msg_state) );
		Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
		Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
		xor_block<State_Bits>( data->key_state, data->msg_state );
		std::memcpy( output, data->key_state, Block_Bytes );
	}

	TEMPLATE_ARGS
	void CLASS::chain_message (Data *data, u8_t const *__restrict input, u64_t num_in_bytes)
	{
		std::memset( data->tweak_state, 0, Tweak_Bytes );
		_CTIME_CONST (u8_t) Initial_Bitwise_Or = (Tweak_First_Bit | static_cast<u8_t>(Type_Mask_E::Msg));
		reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] |= Initial_Bitwise_Or;
		if( num_in_bytes <= State_Bytes ) {
			reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] |= Tweak_Last_Bit;
			data->tweak_state[ 0 ] = static_cast<u64_t>(num_in_bytes);
			std::memcpy( data->msg_state, input, num_in_bytes );
			Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
			Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
			xor_block<State_Bits>( data->key_state, data->msg_state );
			return;
		} else {
			data->tweak_state[ 0 ] = State_Bytes;
			std::memcpy( data->msg_state, input, State_Bytes );
			Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
			Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
			xor_block<State_Bits>( data->key_state, data->msg_state );
			reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] &= Tweak_First_Mask;
			num_in_bytes -= State_Bytes;
			input        += State_Bytes;
		}
		while( num_in_bytes > State_Bytes ) {
			data->tweak_state[ 0 ] += State_Bytes;
			std::memcpy( data->msg_state, input, State_Bytes );
			Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
			Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
			xor_block<State_Bits>( data->key_state, data->msg_state );
			num_in_bytes -= State_Bytes;
			input        += State_Bytes;
		}
		reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_State - 1 ] |= Tweak_Last_Bit;
		data->tweak_state[ 0 ] += num_in_bytes;
		std::memcpy( data->msg_state, input, num_in_bytes );
		std::memset( (data->msg_state + num_in_bytes), 0, State_Bytes - num_in_bytes);
		Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
		Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
		xor_block<State_Bits>( data->key_state, data->msg_state );
	}
	TEMPLATE_ARGS
	void CLASS::chain_output (Data *__restrict data, u8_t *__restrict output, u64_t num_out_bytes)
	{
		std::memset( data->tweak_state, 0, Tweak_Bytes );
		_CTIME_CONST (u8_t) Initial_Bitwise_Or = (Tweak_First_Bit | static_cast<u8_t>(Type_Mask_E::Out));
		reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] |= Initial_Bitwise_Or;
		std::memset( data->msg_state, 0, sizeof(data->msg_state) );
		if( num_out_bytes <= State_Bytes ) {
			reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] |= Tweak_Last_Bit;
			data->tweak_state[ 0 ] = num_out_bytes;
			Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
			Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
			xor_block<State_Bits>( data->key_state, data->msg_state );
			std::memcpy( output, data->key_state, num_out_bytes );
			return;
		} else {
			data->tweak_state[ 0 ] = State_Bytes;
			Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
			Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
			xor_block<State_Bits>( data->key_state, data->msg_state );
			reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_Bytes - 1 ] &= Tweak_First_Mask;
			std::memcpy( output, data->key_state, State_Bytes );
			*(reinterpret_cast<u64_t*>(data->msg_state)) += 1;
			num_out_bytes -= State_Bytes;
			output        += State_Bytes;

		}
		while( num_out_bytes > Block_Bytes ) {
			data->tweak_state[ 0 ] += State_Bytes;
			Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
			Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
			xor_block<State_Bits>( data->key_state, data->msg_state );
			std::memcpy( output, data->key_state, Block_Bytes );
			*(reinterpret_cast<u64_t*>(data->msg_state)) += 1;
			num_out_bytes -= Block_Bytes;
			output        += Block_Bytes;
		}
		reinterpret_cast<u8_t*>(data->tweak_state)[ Tweak_State - 1 ] |= Tweak_Last_Bit;
		data->tweak_state[ 0 ] += num_out_bytes;
		Threefish_f::rekey( &(data->threefish_data), data->key_state, data->tweak_state );
		Threefish_f::cipher( &(data->threefish_data), data->key_state, data->msg_state );
		xor_block<State_Bits>( data->key_state, data->msg_state );
		std::memcpy( output, data->key_state, num_out_bytes );
	}
}/* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
#undef DEFAULT_ARGS
