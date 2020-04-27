/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

#if   !defined (__SSC_CBC_V2__)
#	define  __SSC_CBC_V2__
#else
#	error '__SSC_CBC_V2__ Already Defined'
#endif

#if    defined (OS_PROMPT) || defined (NEW_LINE)
#	error 'Some MACRO we need was already defined'
#endif

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/print.hh>
#include <ssc/files/os_map.hh>
#include <ssc/crypto/cipher_block_chaining_f.hh>

#include "common.hh"

namespace ssc::crypto_impl::cbc_v2
{
	using CBC_f = Cipher_Block_Chaining_F<Block_Bits>;
	_CTIME_CONST (auto&) CBC_V2_ID = "3CRYPT_CBC_V2";
	_CTIME_CONST (int) Salt_Bits = 128;
	_CTIME_CONST (int) Salt_Bytes = Salt_Bits / CHAR_BIT;
	_CTIME_CONST (int) Block_Bits = 512;
	_CTIME_CONST (int) Block_Bytes = Block_Bits / CHAR_BIT;
	_CTIME_CONST (int) Header_Bytes = sizeof(CBC_V2_ID) + sizeof(u64_t) + Tweak_Bytes
		                        + Salt_Bytes        + Block_Bytes   + sizeof(u32_t)
				        + sizeof(u32_t);
	_CTIME_CONST (int) Metadata_Bytes = Header_Bytes + MAC_Bytes;


	void _PUBLIC encrypt (SSPKDF_Input &sspkdf_input,
			      OS_Map &input_map,
			      OS_Map &output_map);
	void _PUBLIC decrypt (OS_Map     &input_map,
			      OS_Map     &output_map,
			      char const *output_filename);
	void _PUBLIC dump_header (OS_Map &input_map,
			          char const *filename);
}/* ~ namespace ssc::crypto_impl */
#undef OS_PROMPT
#undef NEW_LINE
