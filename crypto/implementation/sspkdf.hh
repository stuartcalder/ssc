/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
/* SSC General Headers */
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
/* C Standard Headers */
#include <cstdio>
#include <cstdint>
#include <cstring>
/* C++ Standard Headers */
#include <memory>
/* Local Headers */
#include "common.hh"

namespace ssc::crypto_impl
{
	void _PUBLIC sspkdf (u8_t *output,
		             Skein_t &skein,
		             char const *password,
		             int const  password_length,
		             u8_t const *salt,
		             u32_t const num_iter,
		             u32_t const num_concat);
}/* ~ namespace ssc::crypto_impl */
