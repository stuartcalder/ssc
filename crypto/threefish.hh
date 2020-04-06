/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

#include <climits>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>

#ifndef TEMPLATE_ARGS
#	define TEMPLATE_ARGS	template <int Key_Bits>
#else
#	error 'TEMPLATE_ARGS Already Defined'
#endif
#ifndef CLASS
#	define CLASS		Threefish<Key_Bits>
#else
#	error 'CLASS Already Defined'
#endif

#define THREEFISH_PERFORMANCE	true

namespace ssc
{
	TEMPLATE_ARGS
	class Threefish 
	{
	public:
		/* Static Checks */
		static_assert ((Key_Bits == 256 || Key_Bits == 512 || Key_Bits == 1024), "Invalid keysize");
		static_assert ((CHAR_BIT == 8), "This implementation needs 8-bit chars");
		/* Public Constants */
		_CTIME_CONST (u64_t) Constant_240 = 0x1b'd1'1b'da'a9'fc'1a'22; // Constant_240, defined in the Threefish specification.
		_CTIME_CONST (int) Block_Bits = Key_Bits; // The number of bits in one block: i.e. 256,512, or 1024.
		_CTIME_CONST (int) Block_Bytes = Block_Bits / CHAR_BIT; // The number of bytes in one block.
		_CTIME_CONST (int) Number_Words = Key_Bits / 64; // The number of unsigned 64-bit little endian words in one block.
		_CTIME_CONST (int) Tweak_Words = 2; // The number of unsigned 64-bit little endian words in the tweak.
		_CTIME_CONST (int) Tweak_Bytes = Tweak_Words * sizeof(u64_t); // The number of bytes in the tweak.
		_CTIME_CONST (int) Number_Rounds = []() { // The number of rounds, which is 80 or 72.
							if constexpr (Key_Bits == 1024)
								return 80;
							return 72;
						  }();
		_CTIME_CONST (int) Number_Subkeys = (Number_Rounds / 4) + 1; // The number of subkeys in the key schedule.
		_CTIME_CONST (int) Buffer_Key_Schedule_Words = Number_Subkeys * Number_Words; // The number of 64-bit words in the key schedule buffer.
		_CTIME_CONST (int) Buffer_Key_Schedule_Bytes = Buffer_Key_Schedule_Words * sizeof(u64_t); // The number of bytes in the key schedule buffer.
#if   !defined (THREEFISH_PERFORMANCE) // The 'Key' and 'Tweak' buffers here only exist in the unoptimized version.
		_CTIME_CONST (int) Buffer_Tweak_Words = Tweak_Words + 1; // The number of 64-bit words in the tweak buffer.
		_CTIME_CONST (int) Buffer_Tweak_Bytes = Buffer_Tweak_Words * sizeof(u64_t); // The number of bytes in the tweak buffer.
		_CTIME_CONST (int) Buffer_Key_Words = Number_Words + 1; // The number of 64-bit words in the key buffer.
		_CTIME_CONST (int) Buffer_Key_Bytes = Buffer_Key_Words * sizeof(u64_t); // The number of bytes in the key buffer.
#endif

#if   !defined (THREEFISH_PERFORMANCE)
		// The total number of 64-bit words pointed to by the buffer pointer passed in at runtime.
		_CTIME_CONST (int) Buffer_Words = (Number_Words + Buffer_Key_Schedule_Words + Buffer_Tweak_Words + Buffer_Key_Words);
		// The total number of bytes pointed to by the buffer pointer passed in at runtime.
		_CTIME_CONST (int) Buffer_Bytes = (Block_Bytes + Buffer_Key_Schedule_Bytes + Buffer_Tweak_Bytes + Buffer_Key_Bytes);
#else
		_CTIME_CONST (int) Buffer_Words = (Number_Words + Buffer_Key_Schedule_Words);
		_CTIME_CONST (int) Buffer_Bytes = (Block_Bytes + Buffer_Key_Schedule_Bytes);
#endif
		static_assert (Buffer_Bytes == (Buffer_Words * sizeof(u64_t)));
#if    defined (THREEFISH_PERFORMANCE) /* New Impl */
		_CTIME_CONST (int) External_Key_Buffer_Words = Number_Words + 1; // The number of words of buffer, leaving room for the parity word.
		_CTIME_CONST (int) External_Key_Buffer_Bytes = External_Key_Buffer_Words * sizeof(u64_t);
		_CTIME_CONST (int) External_Tweak_Buffer_Words = Tweak_Words + 1;
		_CTIME_CONST (int) External_Tweak_Buffer_Bytes = External_Tweak_Buffer_Words * sizeof(u64_t);
#endif
		/* Constructors / Destructors */
		Threefish (void) = delete;
#if   !defined (THREEFISH_PERFORMANCE) /* Old Impl */
		Threefish (u64_t *buffer)
			: state{ buffer },
			  key_schedule{ buffer + Number_Words },
			  key{ buffer + (Number_Words + Buffer_Key_Schedule_Words) },
			  tweak{ buffer + (Number_Words + Buffer_Key_Schedule_Words + Buffer_Key_Words) }
		{
		} /* ~ Threefish(u64_t*) */

		Threefish (u64_t *__restrict buffer, u8_t *__restrict k, u8_t *__restrict tw = nullptr)
			: state{ buffer },
			  key_schedule{ buffer + Number_Words },
			  key{ buffer + (Number_Words + Buffer_Key_Schedule_Words) },
			  tweak{ buffer + (Number_Words + Buffer_Key_Schedule_Words + Buffer_Key_Words) }
		{
			expand_key_( k, tw );
		} /* ~ Threefish(u64_t*,u8_t*,u8_t*) */
#else /* New Impl */
		Threefish (u64_t *buffer)
			: state{ buffer },
			  key_schedule{ buffer + Number_Words }
		{
		}
		Threefish (u64_t *__restrict buffer, u8_t *__restrict key, u8_t *__restrict tweak)
			: state{ buffer },
			  key_schedule{ buffer + Number_Words }
		{
			expand_key_( key, tweak );
		}
			  
#endif /* ~ #if !defined (THREEFISH_PERFORMANCE) */
		/* Public Functions */
		void cipher (u8_t *out, u8_t const *in);

		void inverse_cipher (u8_t *out, u8_t const *in);

		void rekey (u8_t *__restrict new_key, u8_t *__restrict new_tweak );
#if    defined (THREEFISH_PERFORMANCE)
		static inline void process_external_keying_material_ (u64_t *key_mat);
		static inline void process_external_tweak_material_ (u64_t *tw_mat);
#endif
	private:
		u64_t * const state;
		u64_t * const key_schedule;
#if   !defined (THREEFISH_PERFORMANCE)
		u64_t * const key;
		u64_t * const tweak;
#endif
		/* Private Functions */
		static void mix_ (u64_t *__restrict x0, u64_t *__restrict x1, int const round, int const index);

		static void inverse_mix_ (u64_t *__restrict x0, u64_t *__restrict x1, int const round, int const index);

		void expand_key_ (u8_t *__restrict key, u8_t *__restrict tweak);

		void add_subkey_ (int const round);

		void subtract_subkey_ (int const round);

		static unsigned int get_rotate_constant_ (int const round, int const index);

		void permute_state_ (void);

		void inverse_permute_state_ (void);
	}; /* ~ class Threefish */

	TEMPLATE_ARGS
	void CLASS::rekey (u8_t *__restrict new_key, u8_t *__restrict new_tweak)
	{
		// Expand the key and tweak arguments into the keyschedule.
		expand_key_( new_key, new_tweak );
	} /* ~ rekey(u8_t*,u8_t*) */

	TEMPLATE_ARGS
	void CLASS::mix_ (u64_t *__restrict x0, u64_t *__restrict x1, int const round, int const index)
	{
		// x0 equal the sum of x0 and x1.
		(*x0) = ((*x0) + (*x1));
		// x1 equals x1 rotated right by a rotation constant defined by the round number and index XOR'd with x0.
		(*x1) = ( rotate_left<u64_t>( (*x1), get_rotate_constant_( round, index ) ) ^ (*x0) );
	} /* ~ mix_(u64_t*,u64_t*,int,int) */

	TEMPLATE_ARGS
	void CLASS::inverse_mix_ (u64_t *__restrict x0, u64_t *__restrict x1, int const round, int const index)
	{
		// x1 equls x0 XOR'd with x1.
		(*x1) = ((*x0) ^ (*x1));
		// x1 equals x1 rotated right by a rotation constant defined by the round number and index.
		(*x1) = rotate_right<u64_t>( (*x1), get_rotate_constant_( round, index ) ) ;
		// x0 equals x0 minus x1.
		(*x0) = (*x0) - (*x1);
	} /* ~ inverse_mix_(u64_t*,u64_t*,int,int) */

	TEMPLATE_ARGS
	unsigned int CLASS::get_rotate_constant_ (int const round, int const index)
	{
		static_assert (Key_Bits == 256 || Key_Bits == 512 || Key_Bits == 1024);
		// All rotation constant look-up tables.
		if constexpr(Key_Bits == 256) {
			_CTIME_CONST(unsigned int) rc [8][2] = {
				{ 14, 16 }, //d = 0
				{ 52, 57 }, //d = 1
				{ 23, 40 }, //d = 2
				{  5, 37 }, //d = 3
				{ 25, 33 }, //d = 4
				{ 46, 12 }, //d = 5
				{ 58, 22 }, //d = 6
				{ 32, 32 }  //d = 7
			};
			return rc[ (round % 8) ][ index ] ;
		} else if constexpr(Key_Bits == 512) {
			_CTIME_CONST(unsigned int) rc [8][4] = {
				{ 46, 36, 19, 37 },
				{ 33, 27, 14, 42 },
				{ 17, 49, 36, 39 },
				{ 44,  9, 54, 56 },
				{ 39, 30, 34, 24 },
				{ 13, 50, 10, 17 },
				{ 25, 29, 39, 43 },
				{  8, 35, 56, 22 }
			};
			return rc[ (round % 8) ][ index ];
		} else if constexpr(Key_Bits == 1024) {
			_CTIME_CONST(unsigned int) rc [8][8] = {
				{ 24, 13,  8, 47,  8, 17, 22, 37 },
				{ 38, 19, 10, 55, 49, 18, 23, 52 },
				{ 33,  4, 51, 13, 34, 41, 59, 17 },
				{  5, 20, 48, 41, 47, 28, 16, 25 },
				{ 41,  9, 37, 31, 12, 47, 44, 30 },
				{ 16, 34, 56, 51,  4, 53, 42, 41 },
				{ 31, 44, 47, 46, 19, 42, 44, 25 },
				{  9, 48, 35, 52, 23, 31, 37, 20 }
			};
			return rc[ (round % 8) ][ index ];
		}
	}/* ~ get_rotate_constant_(int,int) */

#if    defined (THREEFISH_PERFORMANCE)
	TEMPLATE_ARGS
	void CLASS::process_external_keying_material_ (u64_t *key_mat)
	{
#	if     defined (XOR_FOUR)
#		error 'XOR_FOUR Already Defined'
#	else
#		define XOR_FOUR(start)		key_mat[ start ] ^ key_mat[ (start + 1) ] ^ key_mat[ (start + 2) ] ^ key_mat[ (start + 3) ]
#	endif
#	if     defined (XOR_EIGHT)
#		error 'XOR_EIGHT Already Defined'
#	else
#		define XOR_EIGHT(start)		XOR_FOUR (start) ^ XOR_FOUR ((start + 4))
#	endif
#	if     defined (XOR_SIXTEEN)
#		error 'XOR_SIXTEEN Already Defined'
#	else
#		define XOR_SIXTEEN(start)	XOR_EIGHT (start) ^ XOR_EIGHT ((start + 8))
#	endif
		key_mat[ Number_Words ] = Constant_240;
		static_assert (Number_Words == 4 || Number_Words == 8 || Number_Words == 16);
		if constexpr (Number_Words == 4) {
			key_mat[ Number_Words ] ^= XOR_FOUR (0);
		} else if constexpr (Number_Words == 8) {
			key_mat[ Number_Words ] ^= XOR_EIGHT (0);
		} else if constexpr (Number_Words = 16) {
			key_mat[ Number_Words ] ^= XOR_SIXTEEN (0);
		}
#	undef XOR_SIXTEEN
#	undef XOR_EIGHT
#	undef XOR_FOUR
	}
	TEMPLATE_ARGS
	void CLASS::process_external_tweak_material_ (u64_t *tweak_mat)
	{
		tweak_mat[ 2 ] = tweak_mat[ 0 ] ^ tweak_mat[ 1 ];
	}
#endif

	TEMPLATE_ARGS
#if   !defined (THREEFISH_PERFORMANCE)
	void CLASS::expand_key_ (u8_t const *__restrict k, u8_t const *__restrict tw)
#else
	void CLASS::expand_key_ (u8_t *__restrict keying_buf, u8_t *__restrict tweaking_buf)
#endif
	{
#if   !defined (THREEFISH_PERFORMANCE)
		using std::memcpy, std::memset;
		memcpy( key, k, Block_Bytes );
		key[ Number_Words ] = Constant_240;
		for (int i = 0; i < Number_Words; ++i)
			key[ Number_Words ] ^= key[ i ];
		if (tw != nullptr) {
			memcpy( tweak, tw, Tweak_Bytes );
			tweak[ 2 ] = tweak[ 0 ] ^ tweak[ 1 ];
		} else {
			memset( tweak, 0, Buffer_Tweak_Bytes );
		}

		for (int subkey = 0; subkey < Number_Subkeys; ++subkey) {// for each subkey...
			int const subkey_index = subkey * Number_Words;
			for (int i = 0; i <= Number_Words - 4; ++i)// for each word of the subkey, except the last three...
				key_schedule[ subkey_index + i ] = key[ (subkey + i) % (Number_Words + 1) ];
			key_schedule[ subkey_index + (Number_Words - 3) ] =  key[ (subkey + (Number_Words - 3)) % (Number_Words + 1) ] + tweak[ subkey % 3 ];
			key_schedule[ subkey_index + (Number_Words - 2) ] =  key[ (subkey + (Number_Words - 2)) % (Number_Words + 1) ] + tweak[ (subkey + 1) % 3 ];
			key_schedule[ subkey_index + (Number_Words - 1) ] =  key[ (subkey + (Number_Words - 1)) % (Number_Words + 1) ] + static_cast<u64_t>(subkey);
		}
#else
#	if    defined (MAKE_WORD) || defined (MAKE_FOUR_WORDS) || defined (MAKE_EIGHT_WORDS) || defined (MAKE_SIXTEEN_WORDS) \
		|| defined (MAKE_THIRTYTWO_WORDS) || defined (MAKE_SIXTYFOUR_WORDS) || defined (MAKE_SUBKEY)
#		error 'A macro name we need was already defined'
#	endif
#	define MAKE_WORD(index) \
		static_assert (std::is_same<decltype(index),int>::value); \
		key_schedule[ Subkey_Offset + index ] = keying_buf[ (Subkey_Index + index) % (Number_Words + 1) ]
#	define MAKE_FOUR_WORDS(start_index) \
		MAKE_WORD (start_index); MAKE_WORD ((start_index + 1)); MAKE_WORD ((start_index + 2)); MAKE_WORD ((start_index + 3))
#	define MAKE_EIGHT_WORDS(start_index) \
		MAKE_FOUR_WORDS (start_index); MAKE_FOUR_WORDS ((start_index + 4))
#	define MAKE_SUBKEY(index) \
		_MACRO_SHIELD \
			static_assert (std::is_same<decltype(index),int>::value); \
			_CTIME_CONST (int) Subkey_Index = index; \
			_CTIME_CONST (int) Subkey_Offset = index * Number_Words; \
			if constexpr (Number_Words == 4) { \
				MAKE_WORD (0); /* 0 */ \
				MAKE_WORD (1) + tweaking_buf[ Subkey_Index % 3 ]; \
				MAKE_WORD (2) + tweaking_buf[ (Subkey_Index + 1) % 3 ]; \
				MAKE_WORD (3) + Subkey_Index; \
			} else if constexpr (Number_Words == 8) { \
				MAKE_FOUR_WORDS (0); /* 0 - 3 */ \
				MAKE_WORD (4); /* 4 */ \
				MAKE_WORD (5) + tweaking_buf[ Subkey_Index % 3 ]; /* 5 */ \
				MAKE_WORD (6) + tweaking_buf[ (Subkey_Index + 1) % 3 ]; \
				MAKE_WORD (7) + Subkey_Index; \
			} else if constexpr (Number_Words == 16) { \
				MAKE_EIGHT_WORDS (0); /* 0 - 7 */ \
				MAKE_FOUR_WORDS  (8); /* 8 - 11*/ \
				MAKE_WORD       (12); /* 12 */ \
				MAKE_WORD       (13) + tweaking_buf[ Subkey_Index % 3 ]; /* 13 */ \
				MAKE_WORD       (14) + tweaking_buf[ (Subkey_Index + 1) % 3 ]; /* 14 */ \
				MAKE_WORD       (15) + Subkey_Index; \
			} \
		_MACRO_SHIELD_EXIT
		using std::memcpy, std::memset;
		process_external_keying_material_( reinterpret_cast<u64_t *>(keying_buf) );
		process_external_tweak_material_( reinterpret_cast<u64_t *>(tweaking_buf) );
		static_assert (Number_Subkeys == 19 || Number_Subkeys == 21);
		MAKE_SUBKEY  (0); MAKE_SUBKEY  (1); MAKE_SUBKEY  (2);
		MAKE_SUBKEY  (3); MAKE_SUBKEY  (4); MAKE_SUBKEY  (5);
		MAKE_SUBKEY  (6); MAKE_SUBKEY  (7); MAKE_SUBKEY  (8);
		MAKE_SUBKEY  (9); MAKE_SUBKEY (10); MAKE_SUBKEY (11);
		MAKE_SUBKEY (12); MAKE_SUBKEY (13); MAKE_SUBKEY (14);
		MAKE_SUBKEY (15); MAKE_SUBKEY (16); MAKE_SUBKEY (17);
		MAKE_SUBKEY (18);
		if constexpr (Number_Subkeys == 21) {
			MAKE_SUBKEY (19); MAKE_SUBKEY (20);
		}

#	undef MAKE_SUBKEY
#	undef MAKE_EIGHT_WORDS
#	undef MAKE_FOUR_WORDS
#	undef MAKE_WORD
#endif /* ~ #if !defined(THREEFISH_PERFORMANCE) */
	} /* ~ expand_key_(u8_t*,u8_t*) */

	TEMPLATE_ARGS
	void CLASS::add_subkey_	(int const round)
	{
		int const offset = round * (Number_Words / 4);
		for (int i = 0; i < Number_Words; ++i)
			state[ i ] += key_schedule[ offset + i ];
	} /* ~ add_subkey_(int) */

	TEMPLATE_ARGS
	void CLASS::subtract_subkey_ (int const round)
	{
		int const offset = round * (Number_Words / 4);
		for (int i = 0; i < Number_Words; ++i)
			state[ i ] -= key_schedule[ offset + i ];
	} /* ~ subtract_subkey_(int) */

	TEMPLATE_ARGS
	void CLASS::cipher (u8_t *out, u8_t const *in)
	{
		using std::memcpy;

		memcpy( state, in, Block_Bytes );
#if   !defined (THREEFISH_PERFORMANCE)
		for (int round = 0; round < Number_Rounds; ++round) {
			if (round % 4 == 0)
				add_subkey_( round );
			for (int j = 0; j <= ((Number_Words / 2) - 1); ++j)
				mix_( (state + (j*2)), (state + (j*2) + 1), round, j );
			permute_state_();
		}
#else
#	define MIX_(func,round,index) \
		static_assert (std::is_same<decltype(round),int>::value && round >= 0 && round < Number_Rounds); \
		static_assert (std::is_same<decltype(index),int>::value && index >= 0 && index < (Number_Words / 2)); \
		func( (state + (index * 2)), (state + ((index * 2) + 1)), round, index )
#	define MIX_8(func,round,start) \
		MIX_ (func,round,(start + 0)); \
		MIX_ (func,round,(start + 1)); \
		MIX_ (func,round,(start + 2)); \
		MIX_ (func,round,(start + 3)); \
		MIX_ (func,round,(start + 4)); \
		MIX_ (func,round,(start + 5)); \
		MIX_ (func,round,(start + 6)); \
		MIX_ (func,round,(start + 7))
#	define MIX_32(func,round,start) \
		MIX_8 (func,round,(start + 0)); \
		MIX_8 (func,round,(start + 8)); \
		MIX_8 (func,round,(start + 16)); \
		MIX_8 (func,round,(start + 24))
#	define ENC_ROUND(round) \
		if constexpr (round % 4 == 0) \
			add_subkey_( round ); \
		if constexpr (Number_Rounds == 72) { \
			if constexpr (Number_Words == 32) { \
				MIX_8 (mix_,round,0); \
				MIX_8 (mix_,round,8); \
			} else if constexpr (Number_Words == 64) { \
				MIX_32 (mix_,round,0); \
			} \
		} else if constexpr (Number_Rounds == 80) { \
			MIX_32 (mix_,round,0); \
			MIX_32 (mix_,round,32); \
		} \
		permute_state_()
#	define DEC_ROUND(round) \
		inverse_permute_state_(); \
		if constexpr (Number_Rounds == 72) { \
			if constexpr (Number_Words == 32) { \
				MIX_8 (inverse_mix_,round,0); \
				MIX_8 (inverse_mix_,round,8); \
			} else if constexpr (Number_Words == 64) { \
				MIX_32 (inverse_mix_,round,0); \
			} \
		} else if constexpr (Number_Rounds == 80) { \
			MIX_32 (inverse_mix_,round,0); \
			MIX_32 (inverse_mix_,round,32); \
		} \
		if constexpr (round % 4 == 0) \
			subtract_subkey_( round )
#	define EIGHT_ENC_ROUNDS(start) \
		ENC_ROUND (start); ENC_ROUND ((start + 1)); ENC_ROUND ((start + 2)); ENC_ROUND ((start + 3)); \
		ENC_ROUND ((start + 4)); ENC_ROUND ((start + 5)); ENC_ROUND ((start + 6)); ENC_ROUND ((start + 7))
#	define EIGHT_DEC_ROUNDS(start) \
		DEC_ROUND (start); DEC_ROUND ((start - 1)); DEC_ROUND ((start - 2)); DEC_ROUND ((start - 3)); \
		DEC_ROUND ((start - 4)); DEC_ROUND ((start - 5)); DEC_ROUND ((start - 6)); DEC_ROUND ((start - 7))

		EIGHT_ENC_ROUNDS (0); //  0 - 7
		EIGHT_ENC_ROUNDS (8); //  8 - 15
		EIGHT_ENC_ROUNDS (16);// 16 - 23
		EIGHT_ENC_ROUNDS (24);// 24 - 31
		EIGHT_ENC_ROUNDS (32);// 32 - 39
		EIGHT_ENC_ROUNDS (40);// 40 - 47
		EIGHT_ENC_ROUNDS (48);// 48 - 55
		EIGHT_ENC_ROUNDS (56);// 56 - 63
		EIGHT_ENC_ROUNDS (64);// 64 - 71
		if constexpr (Number_Rounds == 80) {
			EIGHT_ENC_ROUNDS (72); //72 - 79
		}
#endif
		add_subkey_( Number_Rounds );
		memcpy( out, state, Block_Bytes );
	} /* ~ cipher(u8_t*,u8_t*) */

	TEMPLATE_ARGS
	void CLASS::inverse_cipher (u8_t *out, u8_t const *in)
	{
		using std::memcpy;
		
		memcpy( state, in, Block_Bytes );
		subtract_subkey_( Number_Rounds );
#if   !defined (THREEFISH_PERFORMANCE)
		for (int round = Number_Rounds - 1; round >= 0; --round) {
			inverse_permute_state_();
			for (int j = 0; j <= ((Number_Words / 2) - 1); ++j)
				inverse_mix_( (state + (j*2)), (state + (j*2) + 1), round, j );
			if (round % 4 == 0)
				subtract_subkey_( round );
		}
#else
		if constexpr (Number_Rounds == 80) {
			EIGHT_DEC_ROUNDS (79); // 79 - 72
		}
		EIGHT_DEC_ROUNDS (71); // 71 - 64
		EIGHT_DEC_ROUNDS (63); // 63 - 56
		EIGHT_DEC_ROUNDS (55); // 55 - //TODO
		EIGHT_DEC_ROUNDS (47); // 47 - //TODO
		EIGHT_DEC_ROUNDS (39); // 39 - //TODO
		EIGHT_DEC_ROUNDS (31); // 31 - //TODO
		EIGHT_DEC_ROUNDS (23); // 23 - //TODO
		EIGHT_DEC_ROUNDS (15); // 15 - //TODO
		EIGHT_DEC_ROUNDS (7);  // 6 - //TODO
#	undef EIGHT_DEC_ROUNDS
#	undef EIGHT_ENC_ROUNDS
#	undef DEC_ROUND
#	undef ENC_ROUND
#	undef MIX_32
#	undef MIX_8
#	undef MIX_

#endif
		memcpy( out, state, Block_Bytes );
	} /* ~ inverse_cipher(u8_t*,u8_t*) */

	TEMPLATE_ARGS
	void CLASS::permute_state_ (void)
	{
		if constexpr(Key_Bits == 256) {
			u64_t w = state[ 1 ];
			state[ 1 ] = state[ 3 ];
			state[ 3 ] = w;
		} else if constexpr(Key_Bits == 512) {
			u64_t w0, w1;
			/* Start from the left. Shift words in and out as necessary
			Starting with index 0 ...*/
			// index 0 overwrites index 6
			w0 = state[ 6 ];
			state[ 6 ] = state[ 0 ];
			// original index 6 (currently w0)
			// overwrites index 4 (saved into w1)
			w1 = state[ 4 ];
			state[ 4 ] = w0;
			// original index 4 (currently w1)
			// overwrites index 2 (saved into w0)
			w0 = state[ 2 ];
			state[ 2 ] = w1;
			// original index 2 (currently w0)
			// overwrites index 0 (doesn't need to be saved, as it was already written into state[6]
			state[ 0 ] = w0;

			/* Index 1 and 5 don't move. All that's left is to swap index 3 and index 7 */
			w0 = state[ 3 ];
			state[ 3 ] = state[ 7 ];
			state[ 7 ] = w0;
		} else if constexpr(Key_Bits == 1024) {
			u64_t w0, w1;
			// 1 overwrites 15 (stored in w0)
			w0 = state[ 15 ];
			state[ 15 ] = state[ 1 ];
			// 15 (in w0) overwrites 7 (stored in w1)
			w1 = state[ 7 ];
			state[ 7 ] = w0;
			// 7 (in w1) overwrites 9 (stored in w0)
			w0 = state[ 9 ];
			state[ 9 ] = w1;
			// 9 (in w0) overwrites 1
			state[ 1 ] = w0;

			// 3 overwrites 11 (stored in w0)
			w0 = state[ 11 ];
			state[ 11 ] = state[ 3 ];
			// 11 (in w0) overwrites 5 (stored in w1)
			w1 = state[ 5 ];
			state[ 5 ] = w0;
			// 5 (in w1) overwrites 13 (stored in w0)
			w0 = state[ 13 ];
			state[ 13 ] = w1;
			// 13 (in w0) overwrites 3
			state[ 3 ] = w0;

			// 4 and 6 are swapped
			w0 = state[ 4 ];
			state[ 4 ] = state[ 6 ];
			state[ 6 ] = w0;

			// 8 overwrites 14 (stored in w0)
			w0 = state[ 14 ];
			state[ 14 ] = state[ 8 ];
			// 14 (in w0) overwrites 12 (stored in w1)
			w1 = state[ 12 ];
			state[ 12 ] = w0;
			// 12 (in w1) overwrites 10 (stored in w0)
			w0 = state[ 10 ];
			state[ 10 ] = w1;
			// 10 (in w0) overwrites 8
			state[ 8 ] = w0;
		}
	} /* ~ permute_state_() */

	TEMPLATE_ARGS
	void CLASS::inverse_permute_state_ (void)
	{
		static_assert (Key_Bits == 256 || Key_Bits == 512 || Key_Bits == 1024);
		if constexpr(Key_Bits == 256) {
			permute_state_();  // here, permute_state() and inverse_permute_state() are the same operation
		} else if constexpr(Key_Bits == 512) {
			u64_t w0, w1;
			/* Starting from the left with index 0 */
			// original index 0
			// overwrites original index 2 (saved into w0)
			w0 = state[ 2 ];
			state[ 2 ] = state[ 0 ];
			// original index 2 (currently in w0)
			// overwrites original index 4 (saved into w1)
			w1 = state[ 4 ];
			state[ 4 ] = w0;
			// original index 4 (currently in w1)
			// overwrites original index 6 (saved into w0)
			w0 = state[ 6 ];
			state[ 6 ] = w1;
			// original index 6 (currently in w0)
			// overwrites original index 0 (doesnt need to be saved)
			state[ 0 ] = w0;
			/* Index 1 and 5 don't move. All that's left is to swap index 3 and index 7 */
			w0 = state[ 3 ];
			state[ 3 ] = state[ 7 ];
			state[ 7 ] = w0;
		} else if constexpr(Key_Bits == 1024) {
			u64_t w0, w1;
			// 1 overwrites 9 (stored in w0)
			w0 = state[ 9 ];
			state[ 9 ] = state[ 1 ];
			// 9 (in w0) overwrites 7 (stored in w1)
			w1 = state[ 7 ];
			state[ 7 ] = w0;
			// 7 (in w1) overwrites 15 (stored in w0)
			w0 = state[ 15 ];
			state[ 15 ] = w1;
			// 15 (in w0) overwrites 1
			state[ 1 ] = w0;

			// 3 overwrites 13 (stored in w0)
			w0 = state[ 13 ];
			state[ 13 ] = state[ 3 ];
			// 13 (in w0) overwrites 5 (stored in w1)
			w1 = state[ 5 ];
			state[ 5 ] = w0;
			// 5 (in w1) overwrites 11 (stored in w0)
			w0 = state[ 11 ];
			state[ 11 ] = w1;
			// 11 (in w0) overwrites 3
			state[ 3 ] = w0;

			// 4 and 6 are swapped
			w0 = state[ 4 ];
			state[ 4 ] = state[ 6 ];
			state[ 6 ] = w0;

			// 8 overwrites 10 (stored in w0)
			w0 = state[ 10 ];
			state[ 10 ] = state[ 8 ];
			// 10 (in w0) overwrites 12 (stored in w1)
			w1 = state[ 12 ];
			state[ 12 ] = w0;
			// 12 (in w1) overwrites 14 (stored in w0)
			w0 = state[ 14 ];
			state[ 14 ] = w1;
			// 14 (in w0) overwrites 8
			state[ 8 ] = w0;
		}
	}/* ~ inverse_permute_state_() */
} /* ~ namespace ssc */
#undef CLASS
#undef TEMPLATE_ARGS
