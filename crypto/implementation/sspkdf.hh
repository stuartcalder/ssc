/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
/* C Standard Headers */
#include <cstdio>
#include <cstdint>
#include <cstring>
/* Local Headers */
#include "common.hh"

namespace ssc::crypto_impl {
	void SSC_PUBLIC
	sspkdf (typename UBI_f::Data       *ubi_data,
	 	SSC_RESTRICT (u8_t*)       output,
	 	SSC_RESTRICT (u8_t const*) password,
	 	int const                  password_size,
	 	SSC_RESTRICT (u8_t const*) salt,
	 	u32_t const                num_iter,
	 	u32_t const                num_concat);
			     
}/* ~ namespace ssc::crypto_impl */
