/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
/* SSC General Headers */
#include <shim/macros.h>
/* C Standard Headers */
#include <cstdio>
#include <cstdint>
#include <cstring>
/* Local Headers */
#include "common.hh"

namespace ssc::crypto_impl {
	void SHIM_PUBLIC
	sspkdf (typename UBI_f::Data * SHIM_RESTRICT ubi_data,
		uint8_t *              SHIM_RESTRICT output,
		uint8_t const *        SHIM_RESTRICT password,
	 	int const                            password_size,
		uint8_t const *        SHIM_RESTRICT salt,
		uint32_t const                       num_iter,
		uint32_t const                       num_concat);
			     
}/* ~ namespace ssc::crypto_impl */
