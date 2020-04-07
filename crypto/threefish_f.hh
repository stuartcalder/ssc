/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

/* C++ Standard Headers */
#include <type_traits>
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
/* SSC Crypto Headers */
#include <ssc/crypto/operations.hh>
/* C Standard Headers */
#include <climits>
#include <cstdlib>
#include <cstring>

#if   !defined (TEMPLATE_ARGS)
#	define TEMPLATE_ARGS	template <int Bits,int Key_Schedule_Gen = 0>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif

#if   !defined (CLASS)
#	define CLASS Threefish_F<Bits,Key_Schedule_Gen>
#else
#	error 'CLASS Already Defined'
#endif

static_assert (CHAR_BIT == 8);
#if   !defined (BITS_TO_BYTES)
#	define BITS_TO_BYTES(bits) (bits / CHAR_BIT)
#else
#	error 'BITS_TO_BYTES Already Defined'
#endif

#if   !defined (BYTES_TO_WORDS)
#	define BYTES_TO_WORDS(bytes) (bytes / sizeof(u64_t)
#else
#	error 'BYTES_TO_WORDS Already Defined'
#endif

namespace ssc
{

	TEMPLATE_ARGS
	class Threefish_F
	{
	public:
		static_assert (Key_Schedule_Gen == 0, "Only support precomputed key-schedules at this time.");
		static_assert (Bits == 256 || Bits == 512 || Bits == 1024);
	/* Key Schedule Control Constants */
		_CTIME_CONST (int) Precomputed_Key_Schedule = 0;
		_CTIME_CONST (int) Runtime_Key_Schedule = 1;
		static_assert (Key_Schedule_Gen == Precomputed_Key_Schedule || Key_Schedule_Gen == Runtime_Key_Schedule);
	/* Constants */
		_CTIME_CONST (int) Block_Bits = Bits;
		_CTIME_CONST (int) Block_Bytes = BITS_TO_BYTES (Block_Bits);
		_CTIME_CONST (int) Block_Words = BYTES_TO_WORDS (Block_Bytes);
		_CTIME_CONST (int) Tweak_Words = 2;
		_CTIME_CONST (int) Tweak_Bytes = Tweak_Words * sizeof(u64_t);
		_CTIME_CONST (int) Number_Rounds = []() {
			if constexpr (Block_Bits == 1024)
				return 80;
			return 72;
		}();
		static_assert (Number_Rounds == 72 || Number_Rounds == 80);
		_CTIME_CONST (int) Number_Subkeys = (Number_Rounds / 4) + 1;
		static_assert (Number_Subkeys == 19 || Number_Subkeys == 21);
		_CTIME_CONST (int) External_Key_Words = Block_Words + 1;
		_CTIME_CONST (int) External_Tweak_Words = Tweak_Words + 1;
		_CTIME_CONST (u64_t) Constant_240 = 0x1b'd1'1b'da'a9'fc'1a'22; // Constant_240, defined in the Threefish specification.

		struct Precomputed_Data {
			u64_t key_schedule [Block_Words * Number_Subkeys];
			u64_t state        [Block_Words];
		};/* ~ struct Precomputed_Data */
		struct Runtime_Data {
			u64_t stored_key   [External_Key_Words];
			u64_t state        [Block_Words];
			u64_t stored_tweak [External_Tweak_Words];
		};/* ~ struct Runtime_Data */

		using Data_t = std::conditional<(Key_Schedule_Gen == Precomputed_Key_Schedule),Precomputed_Data,Runtime_Data>::type;
		static_assert (std::is_same<Data_t,Precomputed_Data>::value || std::is_same<Data_t,Runtime_Data>::value);

		static void rekey          (Data_t *__restrict data, u64_t *__restrict key, u64_t *__restrict tweak);
		static void cipher         (Data_t *__restrict data, u64_t *ctext, u64_t const *ptext);//TODO
		static void inverse_cipher (Data_t *__restrict data, u64_t *ptext, u64_t const *ctext);//TODO
	private:
		template <int round,int index>
		static constexpr int rotate_const_ (void);//TODO
	};/* ~ struct Threefish_F */

	TEMPLATE_ARGS
	void CLASS::rekey (Data_t *__restrict data, u64_t *__restrict key, u64_t *__restrict tweak);
	{
#if    defined (MAKE_WORD) || defined (MAKE_FOUR_WORDS) || defined (MAKE_EIGHT_WORDS) || defined (MAKE_SUBKEY)
#	error 'A macro name we need was already defined'
#endif
#define MAKE_WORD(subkey,i) \
	static_assert (std::is_same<decltype(subkey),int>::value && subkey >= 0 && subkey < Number_Subkeys); \
	static_assert (std::is_same<decltype(i),int>::value && i >= 0 && i < Block_Words); \
	static_assert (Key_Schedule_Gen == Precomputed_Key_Schedule || Key_Schedule_Gen == Runtime_Key_Schedule); \
	data->key_schedule[ (subkey * Block_Words) + i ] = key[ (subkey + i) % (Block_Words + 1) ]

#define MAKE_FOUR_WORDS(subkey,start_i) \
	MAKE_WORD (subkey,start_i); MAKE_WORD (subkey,(start_i + 1)); \
	MAKE_WORD (subkey,(start_i + 2)); MAKE_WORD (subkey,(start_i + 3))

#define MAKE_EIGHT_WORDS(subkey,start_i) \
	MAKE_FOUR_WORDS (subkey,start_i); MAKE_FOUR_WORDS (subkey,(start_i + 4))

#define MAKE_SUBKEY(subkey) \
	_MACRO_SHIELD \
		static_assert (std::is_same<decltype(subkey),int>::value && subkey >= 0 && subkey < Number_Subkeys); \
		if constexpr (Block_Words == 4) { \
			MAKE_WORD (subkey,0); /* 0 */ \
			MAKE_WORD (subkey,1) + tweak[ subkey % 3 ]; \
			MAKE_WORD (subkey,2) + tweak[ (subkey + 1) % 3 ]; \
			MAKE_WORD (subkey,3) + subkey; \
		} else if constexpr (Block_Words == 8) { \
			MAKE_FOUR_WORDS (subkey,0); /* 0 - 3 */ \
			MAKE_WORD (subkey,4); /* 4 */ \
			MAKE_WORD (subkey,5) + tweak[ subkey % 3 ]; /* 5 */ \
			MAKE_WORD (subkey,6) + tweak[ (subkey + 1) % 3 ]; \
			MAKE_WORD (subkey,7) + subkey; \
		} else if constexpr (Block_Words== 16) { \
			MAKE_EIGHT_WORDS (subkey,0); /* 0 - 7 */ \
			MAKE_FOUR_WORDS  (subkey,8); /* 8 - 11*/ \
			MAKE_WORD       (subkey,12); /* 12 */ \
			MAKE_WORD       (subkey,13) + tweak[ subkey % 3 ]; /* 13 */ \
			MAKE_WORD       (subkey,14) + tweak[ (subkey + 1) % 3 ]; /* 14 */ \
			MAKE_WORD       (subkey,15) + subkey; \
		} \
	_MACRO_SHIELD_EXIT
	// Setup the key.
		key[ Block_Words ] = Constant_240;
		static_assert (Block_Words == 4 || Block_Words == 8 || Block_Words == 16);
		if constexpr (Block_Words == 4) {
			key[ Block_Words ] ^= key[ 0 ] ^ key[ 1 ] ^ key[ 2 ] ^ key[ 3 ];
		} else if constexpr (Block_Words == 8) {
			key[ Block_Words ] ^= key[ 0 ] ^ key[ 1 ] ^ key[ 2 ] ^ key[ 3 ]
				            ^ key[ 4 ] ^ key[ 5 ] ^ key[ 6 ] ^ key[ 7 ];
		} else if constexpr (Block_Words == 16) {
			key[ Block_Words ] ^= key[  0 ] ^ key[  1 ] ^ key[  2 ] ^ key[  3 ]
				            ^ key[  4 ] ^ key[  5 ] ^ key[  6 ] ^ key[  7 ]
					    ^ key[  8 ] ^ key[  9 ] ^ key[ 10 ] ^ key[ 11 ]
					    ^ key[ 12 ] ^ key[ 13 ] ^ key[ 14 ] ^ key[ 15 ];
		}
	// Setup the tweak.
		tweak[ 2 ] = tweak[ 0 ] ^ tweak[ 1 ];
		if constexpr (Key_Schedule_Gen == Precomputed_Key_Schedule) {
	// Generate the keyschedule.
			static_assert (Number_Subkeys == 19 || Number_Subkeys == 21);
			MAKE_SUBKEY  (0);
			MAKE_SUBKEY  (1);
			MAKE_SUBKEY  (2);
			MAKE_SUBKEY  (3);
			MAKE_SUBKEY  (4);
			MAKE_SUBKEY  (5);
			MAKE_SUBKEY  (6);
			MAKE_SUBKEY  (7);
			MAKE_SUBKEY  (8);
			MAKE_SUBKEY  (9);
			MAKE_SUBKEY (10);
			MAKE_SUBKEY (11);
			MAKE_SUBKEY (12);
			MAKE_SUBKEY (13);
			MAKE_SUBKEY (14);
			MAKE_SUBKEY (15);
			MAKE_SUBKEY (16);
			MAKE_SUBKEY (17);
			MAKE_SUBKEY (18);
			if constexpr (Number_Subkeys == 21) {
				MAKE_SUBKEY (19);
				MAKE_SUBKEY (20);
			}
		} else if constexpr (Key_Schedule_Gen == Runtime_Key_Schedule) {
			std::memcpy( data->stored_key  , key  , sizeof(data->stored_key)   );
			std::memcpy( data->stored_tweak, tweak, sizeof(data->stored_tweak) );
		}
#undef MAKE_SUBKEY
#undef MAKE_EIGHT_WORDS
#undef MAKE_FOUR_WORDS
#undef MAKE_WORD
	}/* ~ void rekey (...) */

	TEMPLATE_ARGS
	void CLASS::cipher (Data_t *__restrict data, u64_t *ctext, u64_t const *ptext)
	{
#if    defined (MIX) || defined (CALL_MIX) || defined (INVERSE_MIX) || defined (CALL_INVERSE_MIX) || \
       defined (USE_SUBKEY) || || defined (PERMUTE) || defined (INVERSE_PERMUTE) || defined (ENC_ROUND) || \
       defined (DEC_ROUND) ||  defined (EIGHT_ENC_ROUNDS) || defined (EIGHT_DEC_ROUNDS)
#	error 'One Of MIX, CALL_MIX, INVERSE_MIX, CALL_INVERSE_MIX, USE_SUBKEY, \
	       PERMUTE, INVERSE_PERMUTE, ENC_ROUND, DEC_ROUND, EIGHT_ENC_ROUNDS, EIGHT_DEC_ROUNDS Already Defined'
#endif
#	define MIX(word_0,word_1,round,index) \
	static_assert (std::is_same<decltype(word_0),u64_t&>::value); \
	static_assert (std::is_same<decltype(word_1),u64_t&>::value); \
	static_assert (std::is_same<decltype(round),int>::value); \
	static_assert (std::is_same<decltype(index),int>::value); \
	word_0 += word_1; \
	word_1 = ctime_rotate_left< \
			rotate_const_<round,index>(), \
			u64_t \
		> (word_1) ^ word_0

#	define CALL_MIX(round,index) \
	MIX (data->state[ index * 2 ],data->state[ (index * 2) + 1 ],round,index)

#	define INVERSE_MIX(word_0,word_1,round,index) \
	word_1 ^= word_0; \
	word_0 -= ctime_rotate_right< \
			rotate_const<round,index>(), \
			u64_t \
		> (word_1)

#	define CALL_INVERSE_MIX(round,index) \
	INVERSE_MIX (data->state[ index * 2 ],data->state[ (index * 2) + 1 ],round,index)

#	define USE_SUBKEY(operation,round) \
	_MACRO_SHIELD \
		if constexpr (Key_Schedule_Gen == Precomputed_Key_Schedule) { \
			_CTIME_CONST (int) Offset = round * (Block_Words / 4); \
			if constexpr (Block_Words == 4) { \
				data->state[ 0 ] operation data->key_schedule[ Offset     ]; \
				data->state[ 1 ] operation data->key_schedule[ Offset + 1 ]; \
				data->state[ 2 ] operation data->key_schedule[ Offset + 2 ]; \
				data->state[ 3 ] operation data->key_schedule[ Offset + 3 ]; \
			} else if constexpr (Block_Words == 8) { \
				data->state[ 0 ] operation data->key_schedule[ Offset     ]; \
				data->state[ 1 ] operation data->key_schedule[ Offset + 1 ]; \
				data->state[ 2 ] operation data->key_schedule[ Offset + 2 ]; \
				data->state[ 3 ] operation data->key_schedule[ Offset + 3 ]; \
				data->state[ 4 ] operation data->key_schedule[ Offset + 4 ]; \
				data->state[ 5 ] operation data->key_schedule[ Offset + 5 ]; \
				data->state[ 6 ] operation data->key_schedule[ Offset + 6 ]; \
				data->state[ 7 ] operation data->key_schedule[ Offset + 7 ]; \
			} else if constexpr (Block_Words == 16) { \
				data->state[  0 ] operation data->key_schedule[ Offset      ]; \
				data->state[  1 ] operation data->key_schedule[ Offset +  1 ]; \
				data->state[  2 ] operation data->key_schedule[ Offset +  2 ]; \
				data->state[  3 ] operation data->key_schedule[ Offset +  3 ]; \
				data->state[  4 ] operation data->key_schedule[ Offset +  4 ]; \
				data->state[  5 ] operation data->key_schedule[ Offset +  5 ]; \
				data->state[  6 ] operation data->key_schedule[ Offset +  6 ]; \
				data->state[  7 ] operation data->key_schedule[ Offset +  7 ]; \
				data->state[  8 ] operation data->key_schedule[ Offset +  8 ]; \
				data->state[  9 ] operation data->key_schedule[ Offset +  9 ]; \
				data->state[ 10 ] operation data->key_schedule[ Offset + 10 ]; \
				data->state[ 11 ] operation data->key_schedule[ Offset + 11 ]; \
				data->state[ 12 ] operation data->key_schedule[ Offset + 12 ]; \
				data->state[ 13 ] operation data->key_schedule[ Offset + 13 ]; \
				data->state[ 14 ] operation data->key_schedule[ Offset + 14 ]; \
				data->state[ 15 ] operation data->key_schedule[ Offset + 15 ]; \
			} \
		} else if constexpr (Key_Schedule_Gen == Runtime_Key_Schedule) { \
			/*TODO*/ \
		} \
	_MACRO_SHIELD_EXIT

#	define PERMUTE \
		_MACRO_SHIELD \
			if constexpr (Block_Bits == 256) { \
				u64_t w = data->state[ 1 ]; \
				data->state[ 1 ] = data->state[ 3 ]; \
				data->state[ 3 ] = w; \
			} else if constexpr (Block_Bits == 512) { \
				u64_t w0,w1; \
				w0 = data->state[ 6 ]; \
				data->state[ 6 ] = data->state[ 0 ]; \
				w1 = data->state[ 4 ]; \
				data->state[ 4 ] = w0; \
				w0 = data->state[ 2 ]; \
				data->state[ 2 ] = w1; \
				data->state[ 0 ] = w0; \
				w0 = data->state[ 3 ]; \
				data->state[ 3 ] = data->state[ 7 ]; \
				data->state[ 7 ] = w0; \
			} else if constexpr (Block_Bits == 1024) { \
				u64_t w0, w1; \
				w0 = data->state[ 15 ]; \
				data->state[ 15 ] = data->state[ 1 ]; \
				w1 = data->state[ 7 ]; \
				data->state[ 7 ] = w0; \
				w0 = data->state[ 9 ]; \
				data->state[ 9 ] = w1; \
				data->state[ 1 ] = w0; \
				w0 = data->state[ 11 ]; \
				data->state[ 11 ] = data->state[ 3 ]; \
				w1 = data->state[ 5 ]; \
				data->state[ 5 ] = w0; \
				w0 = data->state[ 13 ]; \
				data->state[ 13 ] = w1; \
				data->state[ 3 ] = w0; \
				w0 = data->state[ 4 ]; \
				data->state[ 4 ] = data->state[ 6 ]; \
				data->state[ 6 ] = w0; \
				w0 = data->state[ 14 ]; \
				data->state[ 14 ] = data->state[ 8 ]; \
				w1 = data->state[ 12 ]; \
				data->state[ 12 ] = w0; \
				w0 = data->state[ 10 ]; \
				data->state[ 10 ] = w1; \
				data->state[ 8 ] = w0; \
			} \
		_MACRO_SHIELD_EXIT

#	define INVERSE_PERMUTE \
		_MACRO_SHIELD \
			if constexpr (Block_Bits == 256) { \
				PERMUTE ; \
			} else if constexpr (Block_Bits == 512) { \
				u64_t w0, w1; \
				w0 = state[ 2 ]; \
				state[ 2 ] = state[ 0 ]; \
				w1 = state[ 4 ]; \
				state[ 4 ] = w0; \
				w0 = state[ 6 ]; \
				state[ 6 ] = w1; \
				state[ 0 ] = w0; \
				w0 = state[ 3 ]; \
				state[ 3 ] = state[ 7 ]; \
				state[ 7 ] = w0; \
			} else if constexpr (Block_Bits == 1024) { \
				u64_t w0, w1; \
				w0 = state[ 9 ]; \
				state[ 9 ] = state[ 1 ]; \
				w1 = state[ 7 ]; \
				state[ 7 ] = w0; \
				w0 = state[ 15 ]; \
				state[ 15 ] = w1; \
				state[ 1 ] = w0; \
				w0 = state[ 13 ]; \
				state[ 13 ] = state[ 3 ]; \
				w1 = state[ 5 ]; \
				state[ 5 ] = w0; \
				w0 = state[ 11 ]; \
				state[ 11 ] = w1; \
				state[ 3 ] = w0; \
				w0 = state[ 4 ]; \
				state[ 4 ] = state[ 6 ]; \
				state[ 6 ] = w0; \
				w0 = state[ 10 ]; \
				state[ 10 ] = state[ 8 ]; \
				w1 = state[ 12 ]; \
				state[ 12 ] = w0; \
				w0 = state[ 14 ]; \
				state[ 14 ] = w1; \
				state[ 8 ] = w0; \
			} \
		_MACRO_SHIELD_EXIT

#	define ENC_ROUND(round) \
	static_assert (std::is_same<decltype(round),int>::value && round >= 0 && round < Number_Rounds); \
	if constexpr (round % 4 == 0) \
		USE_SUBKEY (+=,round); \
	if constexpr (Block_Words == 4) { \
		CALL_MIX (round,0); \
		CALL_MIX (round,1); \
	} else if constexpr (Block_Words == 8) { \
		CALL_MIX (round,0); \
		CALL_MIX (round,1); \
		CALL_MIX (round,2); \
		CALL_MIX (round,3); \
	} else if constexpr (Block_Words == 16) { \
		CALL_MIX (round,0); \
		CALL_MIX (round,1); \
		CALL_MIX (round,2); \
		CALL_MIX (round,3); \
		CALL_MIX (round,4); \
		CALL_MIX (round,5); \
		CALL_MIX (round,6); \
		CALL_MIX (round,7); \
	} \
	PERMUTE

#	define DEC_ROUND(round) \
	INVERSE_PERMUTE ; \
	if constexpr (Block_Words == 4) { \
		/*TODO*/ \
	else if constexpr (Block_Words == 8) { \
		/*TODO*/ \
	else if constexpr (Block_Words == 16) { \
		/*TODO*/ \
	}

#	define EIGHT_ENC_ROUNDS(start) \
	ENC_ROUND (start)      ; ENC_ROUND ((start + 1)); ENC_ROUND ((start + 2)); ENC_ROUND ((start + 3)); \
	ENC_ROUND ((start + 4)); ENC_ROUND ((start + 5)): ENC_ROUND ((start + 6)); ENC_ROUND ((start + 7))

		std::memcpy( data->state, ptext, sizeof(data->state) );
		EIGHT_ENC_ROUNDS (0);
		EIGHT_ENC_ROUNDS (8);
		EIGHT_ENC_ROUNDS (16);
		EIGHT_ENC_ROUNDS (24);
		EIGHT_ENC_ROUNDS (32);
		EIGHT_ENC_ROUNDS (40);
		EIGHT_ENC_ROUNDS (48);
		EIGHT_ENC_ROUNDS (56);
		EIGHT_ENC_ROUNDS (64);
		if constexpr (Number_Rounds == 80) {
			EIGHT_ENC_ROUNDS (72);
		}
		USE_SUBKEY (+=,Number_Rounds);
		std::memcpy( ctext, data->state, sizeof(data->state) );

	}/* ~ void cipher (...) */

	TEMPLATE_ARGS
	void CLASS::inverse_cipher (/*TODO*/)
	{
	}/* ~ void inverse_cipher (...) */

	TEMPLATE_ARGS template <int round,int index>
	constexpr int CLASS::rotate_const_ (void)
	{
		static_assert (Block_Bits == 256 || Block_Bits == 512 || Block_Bits == 1024);
		if constexpr (Block_Bits == 256) {
			static_assert (round >= 0 && round <= 18);
			static_assert (index == 0 || index == 1);
			_CTIME_CONST (int) rc [8][2] = {
				{ 14, 16 }, //d = 0
				{ 52, 57 }, //d = 1
				{ 23, 40 }, //d = 2
				{  5, 37 }, //d = 3
				{ 25, 33 }, //d = 4
				{ 46, 12 }, //d = 5
				{ 58, 22 }, //d = 6
				{ 32, 32 }  //d = 7
			};
			return rc[ round % 8 ][ index ];
		} else if constexpr (Block_Bits == 512) {
			static_assert (round >= 0 && round <= 18);
			static_assert (index >= 0 && index <= 3);
			_CTIME_CONST (int) rc [8][4] = {
				{ 46, 36, 19, 37 },
				{ 33, 27, 14, 42 },
				{ 17, 49, 36, 39 },
				{ 44,  9, 54, 56 },
				{ 39, 30, 34, 24 },
				{ 13, 50, 10, 17 },
				{ 25, 29, 39, 43 },
				{  8, 35, 56, 22 }
			};
			return rc[ round % 8 ][ index ];
		} else if constexpr (Block_Bits == 1024) {
			static_assert (round >= 0 && round <= 20);
			static_assert (index >= 0 && index <= 7);
			_CTIME_CONST (int) rc [8][8] = {
				{ 24, 13,  8, 47,  8, 17, 22, 37 },
				{ 38, 19, 10, 55, 49, 18, 23, 52 },
				{ 33,  4, 51, 13, 34, 41, 59, 17 },
				{  5, 20, 48, 41, 47, 28, 16, 25 },
				{ 41,  9, 37, 31, 12, 47, 44, 30 },
				{ 16, 34, 56, 51,  4, 53, 42, 41 },
				{ 31, 44, 47, 46, 19, 42, 44, 25 },
				{  9, 48, 35, 52, 23, 31, 37, 20 }
			};
			return rc[ round % 8 ][ index ];
		}
	}
}/* ~ namespace ssc */
#undef BYTES_TO_WORDS
#undef BITS_TO_BYTES
#undef CLASS
#undef TEMPLATE_ARGS
