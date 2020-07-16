/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#if   !defined (SSC_FEATURE_CBC_V2)
#	define  SSC_FEATURE_CBC_V2
#else
#	error 'SSC_FEATURE_CBC_V2 already defined!'
#endif

#if    defined (OS_PROMPT_) || defined (NEW_LINE_)
#	error 'Some MACRO we need was already defined'
#endif

#include <shim/macros.h>
#include <shim/print.h>
#include <shim/map.h>
#include <shim/mlock.h>
#include <shim/operations.h>

#include <ssc/crypto/cipher_block_chaining_f.hh>

#include "common.hh"

namespace ssc::crypto_impl::cbc_v2 {
	using CBC_f = Cipher_Block_Chaining_F<Block_Bits>;
	static constexpr auto &CBC_V2_ID = "3CRYPT_CBC_V2";
	enum Int_Constants: int {
		Salt_Bits = 128,
		Salt_Bytes = Salt_Bits / CHAR_BIT,
		Block_Bits = 512,
		Block_Bytes = Block_Bits / CHAR_BIT,
		Header_Bytes = sizeof(CBC_V2_ID) + sizeof(uint64_t) + Tweak_Bytes + Salt_Bytes + Block_Bytes + (2 * sizeof(uint32_t)),
		Metadata_Bytes = Header_Bytes + MAC_Bytes
	};

	void SHIM_PUBLIC
	encrypt (SSPKDF_Input & SHIM_RESTRICT sspkdf_input,
		 Shim_Map &     SHIM_RESTRICT input_map,
		 Shim_Map &     SHIM_RESTRICT output_map)

	void SHIM_PUBLIC
	decrypt (Shim_Map &   SHIM_RESTRICT input_map,
		 Shim_Map &   SHIM_RESTRICT output_map,
		 char const * SHIM_RESTRICT output_filename);

	void SHIM_PUBLIC
	dump_header (Shim_Map &   SHIM_RESTRICT input_map,
		     char const * SHIM_RESTRICT filename);
}/* ~ namespace ssc::crypto_impl */
#undef OS_PROMPT_
#undef NEW_LINE_
