/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

/* C++ Std
 */
#include <type_traits>
/* SSC General
 */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
/* SSC Crypto
 */
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/constants.hh>
/* C Std
 */
#include <climits>
#include <cstdlib>
#include <cstring>

#if    defined (DEFAULT_ARGS) || defined (TEMPLATE_ARGS) || defined (CLASS)
#	error 'One of DEFAULT_ARGS, TEMPLATE_ARGS, CLASS was already defined'
#endif
#define DEFAULT_ARGS	template <int Bits,Key_Schedule_E Key_Schedule_Gen = Key_Schedule_E::Stored>
#define TEMPLATE_ARGS	template <int Bits,Key_Schedule_E Key_Schedule_Gen>
#define CLASS Threefish_F<Bits,Key_Schedule_Gen>

namespace ssc
{

	DEFAULT_ARGS
	class Threefish_F
	{
	public:
		static_assert (CHAR_BIT      == 8,"This code assumes 8-bit bytes.");
		static_assert (sizeof(u64_t) == 8,"This code assumes 64-bit integers are 8 bytes large.");
		static_assert (Bits == 256 ||
			       Bits == 512 ||
			       Bits == 1024,
			       "The Threefish block cipher is defined only for 256, 512, 1024 bits.");
	/* Key Schedule Control Constants
	 */
		static_assert (Key_Schedule_Gen == Key_Schedule_E::Stored ||
			       Key_Schedule_Gen == Key_Schedule_E::On_Demand);
		Threefish_F (void) = delete;
	/* Constants
	 */
		enum Int_Constants : int {
			Block_Bits    = Bits,
			Block_Bytes   = Block_Bits / CHAR_BIT,
			Block_Words   = Block_Bytes / sizeof(u64_t),
			Tweak_Words   = 2,
			Tweak_Bytes   = Tweak_Words * sizeof(u64_t),
			Tweak_Bits    = Tweak_Bytes * CHAR_BIT,
			Number_Rounds = [](){
				if constexpr (Block_Bits == 1024)
					return 80;
				return 72;
			}(),
			Number_Subkeys       = (Number_Rounds / 4) + 1,
			External_Key_Words   = Block_Words + 1,
			External_Tweak_Words = Tweak_Words + 1
		};
		static_assert (Number_Rounds == 72 || Number_Rounds == 80,
			       "Threefish 1024 uses 80 rounds, 256 and 512 use 72 rounds.");
		static_assert (Number_Subkeys == 19 || Number_Subkeys == 21,
			       "Given a choice of 72 and 80 rounds, there may only be 19 or 21 subkeys.");
		enum U64_Constants : u64_t {
			Constant_240 = 0x1b'd1'1b'da'a9'fc'1a'22
		};

		struct Stored_Data {
		/* When we compute once then store all the subkeys of the key schedule, we store them in $key_schedule.
		 */
			u64_t key_schedule [Block_Words * Number_Subkeys];
			u64_t state        [Block_Words];
		};// ~ struct Precomputed_Data
		struct On_Demand_Data {
		/* When we compute the subkeys at runtime, we store pointers to the input key and tweak.
		 */
			u64_t state        [Block_Words];
			u64_t *stored_key;  // -> [External_Key_Words]
			u64_t *stored_tweak;// -> [External_Tweak_Words]
		};// ~ struct Runtime_Data

	/* Data_t refers to Stored_Data or Runtime_Data depending on which
	 * alias is selected.
	 */
		using Data_t = typename std::conditional<(Key_Schedule_Gen == Key_Schedule_E::Stored),Stored_Data,On_Demand_Data>::type;
		static_assert (std::is_same<Data_t,Stored_Data>::value || std::is_same<Data_t,On_Demand_Data>::value);

		static void rekey          (_RESTRICT (Data_t *) data,
				            _RESTRICT (u64_t *)  key,
					    _RESTRICT (u64_t *)  tweak);

		static void cipher         (_RESTRICT (Data_t *)     data,
				            _RESTRICT (u8_t *)       ctext,
					    _RESTRICT (u8_t const *) ptext);

		static void inverse_cipher (_RESTRICT (Data_t *)     data,
				            _RESTRICT (u8_t *)       ptext,
					    _RESTRICT (u8_t const *) ctext);
	private:
		template <int round,int index>
		static constexpr int rotate_const_ (void);
	};// ~ class Threefish_F

	TEMPLATE_ARGS
	void CLASS::rekey (_RESTRICT (Data_t *) data,
                           _RESTRICT (u64_t *)  key,
                           _RESTRICT (u64_t *)  tweak)
	{
#if    defined (MAKE_WORD) || defined (SET_WORDS) || defined (SET_FOUR_WORDS) || defined (SET_EIGHT_WORDS) || defined (MAKE_SUBKEY)
#	error 'A macro name we need was already defined'
#endif
#define MAKE_WORD(key_var,subkey,i) \
	key_var[ (subkey + i) % (Block_Words + 1) ]

#define SET_WORD(subkey,i) \
	static_assert (std::is_same<decltype(subkey),int>::value && subkey >= 0 && subkey < Number_Subkeys, \
		       "Ensure the subkey is an integer, and within the range of valid subkeys."); \
	static_assert (std::is_same<decltype(i),int>::value && i >= 0 && i < Block_Words, \
		       "Ensure the index i is an integer, and within the range of valid indices"); \
	static_assert (Key_Schedule_Gen == Key_Schedule_E::Stored|| Key_Schedule_Gen == Key_Schedule_E::On_Demand, \
		       "Ensure the key schedule is precisely specified as precomputed, or runtime computed."); \
	data->key_schedule[ (subkey * Block_Words) + i ] = MAKE_WORD (key,subkey,i)

#define SET_FOUR_WORDS(subkey,start_i) \
	SET_WORD (subkey,start_i); SET_WORD (subkey,(start_i + 1)); \
	SET_WORD (subkey,(start_i + 2)); SET_WORD (subkey,(start_i + 3))

#define SET_EIGHT_WORDS(subkey,start_i) \
	SET_FOUR_WORDS (subkey,start_i); SET_FOUR_WORDS (subkey,(start_i + 4))

#define MAKE_SUBKEY(subkey) \
	_MACRO_SHIELD \
		static_assert (std::is_same<decltype(subkey),int>::value && subkey >= 0 && subkey < Number_Subkeys, \
			       "Ensure the subkey is an integer, and within the valid range of subkey values."); \
		if constexpr (Block_Words == 4) { \
			SET_WORD (subkey,0); /* 0 */ \
			SET_WORD (subkey,1) + tweak[ subkey % 3 ]; \
			SET_WORD (subkey,2) + tweak[ (subkey + 1) % 3 ]; \
			SET_WORD (subkey,3) + subkey; \
		} else if constexpr (Block_Words == 8) { \
			SET_FOUR_WORDS (subkey,0); /* 0 - 3 */ \
			SET_WORD (subkey,4); /* 4 */ \
			SET_WORD (subkey,5) + tweak[ subkey % 3 ]; /* 5 */ \
			SET_WORD (subkey,6) + tweak[ (subkey + 1) % 3 ]; \
			SET_WORD (subkey,7) + subkey; \
		} else if constexpr (Block_Words == 16) { \
			SET_EIGHT_WORDS (subkey,0); /* 0 - 7 */ \
			SET_FOUR_WORDS  (subkey,8); /* 8 - 11*/ \
			SET_WORD       (subkey,12); /* 12 */ \
			SET_WORD       (subkey,13) + tweak[ subkey % 3 ]; /* 13 */ \
			SET_WORD       (subkey,14) + tweak[ (subkey + 1) % 3 ]; /* 14 */ \
			SET_WORD       (subkey,15) + subkey; \
		} \
	_MACRO_SHIELD_EXIT
	/* Setup the key.
	 */
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
	/* Setup the tweak.
	 */
		tweak[ 2 ] = tweak[ 0 ] ^ tweak[ 1 ];
		if constexpr (Key_Schedule_Gen == Key_Schedule_E::Stored) {
		// A pre-computed key-schedule has been asked for.. Generate all the subkeys and stored them in $key_schedule.
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
		} else if constexpr (Key_Schedule_Gen == Key_Schedule_E::On_Demand) {
		// An On-Demand-computed key-schedule has been asked for.. Store pointers to the key and tweak for accessing later.
			data->stored_key = key;
			data->stored_tweak = tweak;
		}
	}// ~ void rekey (...)

	TEMPLATE_ARGS
	void CLASS::cipher (_RESTRICT (Data_t *)     data,
                            _RESTRICT (u8_t *)       ctext,
                            _RESTRICT (u8_t const *) ptext)
	{
#if    defined (MIX) || defined (CALL_MIX) || defined (INVERSE_MIX) || defined (CALL_INVERSE_MIX) || \
       defined (USE_SUBKEY) || defined (PERMUTE) || defined (INVERSE_PERMUTE) || defined (ENC_ROUND) || \
       defined (DEC_ROUND) ||  defined (EIGHT_ENC_ROUNDS) || defined (EIGHT_DEC_ROUNDS)
#	error 'One Of MIX, CALL_MIX, INVERSE_MIX, CALL_INVERSE_MIX, USE_SUBKEY, \
	       PERMUTE, INVERSE_PERMUTE, ENC_ROUND, DEC_ROUND, EIGHT_ENC_ROUNDS, EIGHT_DEC_ROUNDS Already Defined'
#endif
#	define MIX(word_0,word_1,round,index) \
	static_assert (std::is_same<decltype(word_0),u64_t&>::value, \
		       "word_0 must be an unsigned 64-bit integer reference."); \
	static_assert (std::is_same<decltype(word_1),u64_t&>::value, \
		       "word_1 must be an unsigned 64-bit integer reference."); \
	static_assert (std::is_same<decltype(round),int>::value, \
		       "round must be an integer."); \
	static_assert (std::is_same<decltype(index),int>::value, \
		       "index must be an integer."); \
	word_0 += word_1; \
	word_1 = rotate_left< \
			rotate_const_<round,index>(), \
			u64_t \
		> (word_1) ^ word_0

#	define CALL_MIX(round,index) \
	MIX (data->state[ index * 2 ],data->state[ (index * 2) + 1 ],round,index)

#	define INVERSE_MIX(word_0,word_1,round,index) \
	word_1 ^= word_0; \
	word_1 = rotate_right< \
			rotate_const_<round,index>(), \
			u64_t \
		> (word_1); \
	word_0 -= word_1

#	define CALL_INVERSE_MIX(round,index) \
	INVERSE_MIX (data->state[ index * 2 ],data->state[ (index * 2) + 1 ],round,index)

#	define USE_SUBKEY(operation,round) \
	_MACRO_SHIELD \
		_CTIME_CONST (int) Subkey_Index = round / 4; \
		if constexpr (Key_Schedule_Gen == Key_Schedule_E::Stored) { \
		/* The key-schedule has been pre-computed, thus we can modify the state by directly accessing
		 * the keyschedule, where operation is += or -= for adding or subtracting the subkey from the state
		 * words.*/ \
			_CTIME_CONST (int) Subkey_Offset = Subkey_Index * Block_Words; \
			if constexpr (Block_Words == 4) { \
				data->state[ 0 ] operation data->key_schedule[ Subkey_Offset + 0 ]; \
				data->state[ 1 ] operation data->key_schedule[ Subkey_Offset + 1 ]; \
				data->state[ 2 ] operation data->key_schedule[ Subkey_Offset + 2 ]; \
				data->state[ 3 ] operation data->key_schedule[ Subkey_Offset + 3 ]; \
			} else if constexpr (Block_Words == 8) { \
				data->state[ 0 ] operation data->key_schedule[ Subkey_Offset + 0 ]; \
				data->state[ 1 ] operation data->key_schedule[ Subkey_Offset + 1 ]; \
				data->state[ 2 ] operation data->key_schedule[ Subkey_Offset + 2 ]; \
				data->state[ 3 ] operation data->key_schedule[ Subkey_Offset + 3 ]; \
				data->state[ 4 ] operation data->key_schedule[ Subkey_Offset + 4 ]; \
				data->state[ 5 ] operation data->key_schedule[ Subkey_Offset + 5 ]; \
				data->state[ 6 ] operation data->key_schedule[ Subkey_Offset + 6 ]; \
				data->state[ 7 ] operation data->key_schedule[ Subkey_Offset + 7 ]; \
			} else if constexpr (Block_Words == 16) { \
				data->state[  0 ] operation data->key_schedule[ Subkey_Offset +  0 ]; \
				data->state[  1 ] operation data->key_schedule[ Subkey_Offset +  1 ]; \
				data->state[  2 ] operation data->key_schedule[ Subkey_Offset +  2 ]; \
				data->state[  3 ] operation data->key_schedule[ Subkey_Offset +  3 ]; \
				data->state[  4 ] operation data->key_schedule[ Subkey_Offset +  4 ]; \
				data->state[  5 ] operation data->key_schedule[ Subkey_Offset +  5 ]; \
				data->state[  6 ] operation data->key_schedule[ Subkey_Offset +  6 ]; \
				data->state[  7 ] operation data->key_schedule[ Subkey_Offset +  7 ]; \
				data->state[  8 ] operation data->key_schedule[ Subkey_Offset +  8 ]; \
				data->state[  9 ] operation data->key_schedule[ Subkey_Offset +  9 ]; \
				data->state[ 10 ] operation data->key_schedule[ Subkey_Offset + 10 ]; \
				data->state[ 11 ] operation data->key_schedule[ Subkey_Offset + 11 ]; \
				data->state[ 12 ] operation data->key_schedule[ Subkey_Offset + 12 ]; \
				data->state[ 13 ] operation data->key_schedule[ Subkey_Offset + 13 ]; \
				data->state[ 14 ] operation data->key_schedule[ Subkey_Offset + 14 ]; \
				data->state[ 15 ] operation data->key_schedule[ Subkey_Offset + 15 ]; \
			} \
		} else if constexpr (Key_Schedule_Gen == Key_Schedule_E::On_Demand) { \
		/* The key-schedule is computed on-demand. For each += or -= operation, we compute
		 * the subkeys on-demand. */ \
			if constexpr (Block_Words == 4) { \
				data->state[ 0 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,0)); \
				data->state[ 1 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,1) + data->stored_tweak[ Subkey_Index % 3 ]); \
				data->state[ 2 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,2) + data->stored_tweak[ (Subkey_Index + 1) % 3 ]); \
				data->state[ 3 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,3) + Subkey_Index); \
			} else if constexpr (Block_Words == 8) { \
				data->state[ 0 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,0)); \
				data->state[ 1 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,1)); \
				data->state[ 2 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,2)); \
				data->state[ 3 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,3)); \
				data->state[ 4 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,4)); \
				data->state[ 5 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,5) + data->stored_tweak[ Subkey_Index % 3 ]); \
				data->state[ 6 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,6) + data->stored_tweak[ (Subkey_Index + 1) % 3 ]); \
				data->state[ 7 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,7) + Subkey_Index); \
			} else if constexpr (Block_Words == 16) { \
				data->state[  0 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 0)); \
				data->state[  1 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 1)); \
				data->state[  2 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 2)); \
				data->state[  3 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 3)); \
				data->state[  4 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 4)); \
				data->state[  5 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 5)); \
				data->state[  6 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 6)); \
				data->state[  7 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 7)); \
				data->state[  8 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 8)); \
				data->state[  9 ] operation (MAKE_WORD (data->stored_key,Subkey_Index, 9)); \
				data->state[ 10 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,10)); \
				data->state[ 11 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,11)); \
				data->state[ 12 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,12)); \
				data->state[ 13 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,13) + data->stored_tweak[ Subkey_Index % 3 ]); \
				data->state[ 14 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,14) + data->stored_tweak[ (Subkey_Index + 1) % 3 ]); \
				data->state[ 15 ] operation (MAKE_WORD (data->stored_key,Subkey_Index,15) + Subkey_Index); \
			} \
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
				w0 = data->state[ 2 ]; \
				data->state[ 2 ] = data->state[ 0 ]; \
				w1 = data->state[ 4 ]; \
				data->state[ 4 ] = w0; \
				w0 = data->state[ 6 ]; \
				data->state[ 6 ] = w1; \
				data->state[ 0 ] = w0; \
				w0 = data->state[ 3 ]; \
				data->state[ 3 ] = data->state[ 7 ]; \
				data->state[ 7 ] = w0; \
			} else if constexpr (Block_Bits == 1024) { \
				u64_t w0, w1; \
				w0 = data->state[ 9 ]; \
				data->state[ 9 ] = data->state[ 1 ]; \
				w1 = data->state[ 7 ]; \
				data->state[ 7 ] = w0; \
				w0 = data->state[ 15 ]; \
				data->state[ 15 ] = w1; \
				data->state[ 1 ] = w0; \
				w0 = data->state[ 13 ]; \
				data->state[ 13 ] = data->state[ 3 ]; \
				w1 = data->state[ 5 ]; \
				data->state[ 5 ] = w0; \
				w0 = data->state[ 11 ]; \
				data->state[ 11 ] = w1; \
				data->state[ 3 ] = w0; \
				w0 = data->state[ 4 ]; \
				data->state[ 4 ] = data->state[ 6 ]; \
				data->state[ 6 ] = w0; \
				w0 = data->state[ 10 ]; \
				data->state[ 10 ] = data->state[ 8 ]; \
				w1 = data->state[ 12 ]; \
				data->state[ 12 ] = w0; \
				w0 = data->state[ 14 ]; \
				data->state[ 14 ] = w1; \
				data->state[ 8 ] = w0; \
			} \
		_MACRO_SHIELD_EXIT

#	define ENC_ROUND(round) \
	static_assert (std::is_same<decltype(round),int>::value && round >= 0 && round < Number_Rounds, \
		       "Enforce that round is an integer, from 0 to less than the number of threefish rounds."); \
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
		CALL_INVERSE_MIX (round,0); \
		CALL_INVERSE_MIX (round,1); \
	} else if constexpr (Block_Words == 8) { \
		CALL_INVERSE_MIX (round,0); \
		CALL_INVERSE_MIX (round,1); \
		CALL_INVERSE_MIX (round,2); \
		CALL_INVERSE_MIX (round,3); \
	} else if constexpr (Block_Words == 16) { \
		CALL_INVERSE_MIX (round,0); \
		CALL_INVERSE_MIX (round,1); \
		CALL_INVERSE_MIX (round,2); \
		CALL_INVERSE_MIX (round,3); \
		CALL_INVERSE_MIX (round,4); \
		CALL_INVERSE_MIX (round,5); \
		CALL_INVERSE_MIX (round,6); \
		CALL_INVERSE_MIX (round,7); \
	} \
	if constexpr (round % 4 == 0) \
		USE_SUBKEY (-=,round)

#	define EIGHT_ENC_ROUNDS(start) \
	ENC_ROUND (start      ); ENC_ROUND ((start + 1)); ENC_ROUND ((start + 2)); ENC_ROUND ((start + 3)); \
	ENC_ROUND ((start + 4)); ENC_ROUND ((start + 5)); ENC_ROUND ((start + 6)); ENC_ROUND ((start + 7))

#	define EIGHT_DEC_ROUNDS(start) \
	DEC_ROUND (start      ); DEC_ROUND ((start - 1)); DEC_ROUND ((start - 2)); DEC_ROUND ((start - 3)); \
	DEC_ROUND ((start - 4)); DEC_ROUND ((start - 5)); DEC_ROUND ((start - 6)); DEC_ROUND ((start - 7))

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

	}// ~ void cipher (...)

	TEMPLATE_ARGS
	void CLASS::inverse_cipher (_RESTRICT (Data_t *)     data,
			            _RESTRICT (u8_t *)       ptext,
				    _RESTRICT (u8_t const *) ctext)
	{
		std::memcpy( data->state, ctext, sizeof(data->state) );
		USE_SUBKEY (-=,Number_Rounds);
		if constexpr (Number_Rounds == 80) {
			EIGHT_DEC_ROUNDS (79);
		}
		EIGHT_DEC_ROUNDS (71);
		EIGHT_DEC_ROUNDS (63);
		EIGHT_DEC_ROUNDS (55);
		EIGHT_DEC_ROUNDS (47);
		EIGHT_DEC_ROUNDS (39);
		EIGHT_DEC_ROUNDS (31);
		EIGHT_DEC_ROUNDS (23);
		EIGHT_DEC_ROUNDS (15);
		EIGHT_DEC_ROUNDS (7);
		std::memcpy( ptext, data->state, sizeof(data->state) );
	}// ~ void inverse_cipher (...)

	TEMPLATE_ARGS template <int round,int index>
	constexpr int CLASS::rotate_const_ (void)
	{
		static_assert (Block_Bits == 256 || Block_Bits == 512 || Block_Bits == 1024);
		if constexpr (Block_Bits == 256) {
			static_assert (index == 0 || index == 1);
			constexpr int rc [8][2] = {
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
			static_assert (index >= 0 && index <= 3);
			constexpr int rc [8][4] = {
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
			static_assert (index >= 0 && index <= 7);
			constexpr int rc [8][8] = {
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
	}// ~ constexpr int rotate_const_ (...)
}// ~ namespace ssc
#undef EIGHT_DEC_ROUNDS
#undef EIGHT_ENC_ROUNDS
#undef DEC_ROUND
#undef ENC_ROUND
#undef INVERSE_PERMUTE
#undef PERMUTE
#undef USE_SUBKEY
#undef CALL_INVERSE_MIX
#undef INVERSE_MIX
#undef CALL_MIX
#undef MIX
#undef MAKE_SUBKEY
#undef SET_EIGHT_WORDS
#undef SET_FOUR_WORDS
#undef SET_WORD
#undef MAKE_WORD
#undef CLASS
#undef TEMPLATE_ARGS
#undef DEFAULT_ARGS
