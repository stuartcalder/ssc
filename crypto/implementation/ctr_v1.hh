/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once

#ifndef __SSC_CTR_V1__
#	define __SSC_CTR_V1__
#else
#	error 'Already defined'
#endif

// We will enable this define when we are ready to test the upcoming reimplementation of CTR_V1, to using CATENA-SKEIN instead of SSPKDF.
#if 0
#	define NEW_IMPL
#endif

#include "common.hh"

#include <cstring>
#include <cstdlib>
#include <string>
#include <climits>

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/ctr.hh>

namespace ssc::crypto_impl::ctr_v1 {
	_CTIME_CONST(auto &)	CTR_V1_ID = "SSC_CTR_V1";
	// We require the block cipher to have at least 128 bits.
	static_assert (Block_Bits >= 128);
	// We require the block bits to be divisible by 2, to cleanly mark half of them as nonce.
	static_assert (Block_Bits % 2 == 0);
	// We require that a char be 8 bits.
	static_assert (CHAR_BIT == 8);
	_CTIME_CONST(int) Nonce_Bits = Block_Bits / 2;
	_CTIME_CONST(int) Nonce_Bytes = Nonce_Bits / CHAR_BIT;
	// We'll be using the Threefish block cipher in CTR mode here.
	using CTR_t = CTR_Mode<Threefish_t, Block_Bits>;

#ifdef NEW_IMPL
	//TODO
#else
	struct _PUBLIC CTR_V1_Header {
		char		 id		[sizeof(CTR_V1_ID)];
		u64_t		 total_size;
		u8_t		 tweak		[Tweak_Bytes];
		u8_t		 sspkdf_salt	[Salt_Bytes];
		u8_t		 ctr_nonce	[Nonce_Bytes];
		u32_t		 num_iter;
		u32_t		 num_concat;
		_CTIME_CONST(int) Total_Size = sizeof(id) + sizeof(total_size) + sizeof(tweak) + sizeof(sspkdf_salt) + sizeof(ctr_nonce) + sizeof(num_iter) + sizeof(num_concat);
	};

	_CTIME_CONST(int)	Metadata_Bytes = CTR_V1_Header::Total_Size + MAC_Bytes;
#endif

	void _PUBLIC
	encrypt (Input const & input_abstr);

	void _PUBLIC
	decrypt (char const *__restrict input_filename,
	 	 char const *__restrict output_filename);

	void _PUBLIC
	dump_header (char const *filename);

}/*namespace ssc::crypto_impl::ctr_v1*/
