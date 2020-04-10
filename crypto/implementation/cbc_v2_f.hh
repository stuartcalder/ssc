#pragma once

#if   !defined (__SSC_CBC_V2__)
#	define  __SSC_CBC_V2__
#else
#	error '__SSC_CBC_V2__ Already Defined'
#endif

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/files/os_map.hh>
#include <ssc/crypto/cipher_block_chaining_f.hh>

#include "common.hh"

namespace ssc::crypto_impl
{
	_CTIME_CONST (auto&) CBC_V2_ID = "3CRYPT_CBC_V2";
	using CBC_f = Cipher_Block_Chaining_F<512>;

	void _PUBLIC
	encrypt (/*TODO*/
}/* ~ namespace ssc::crypto_impl */
