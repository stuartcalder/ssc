/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once

namespace ssc
{
	/* This struct does nothing.
	 * It is used to uniquely identify when no class is defined, usually in template parameters that take
	 * typenames as arguments, analogous to NULL and nullptr.
	 */
	struct Null_Type
	{
		Null_Type() = delete;
	};/* ~ struct Null_Type */
}/* ~ namespace ssc */
