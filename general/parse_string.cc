/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include <utility>
#include "parse_string.hh"
#include <ssc/general/error_conditions.hh>

namespace ssc
{
	int shift_left_digits (char *c_str, int size)
	{
		int index = 0;
		for( int i = 0; i < size; ++i )
			if( std::isdigit( c_str[ i ] ) )
				c_str[ index++ ] = c_str[ i ];
		if( (index + 1) < size )
			c_str[ index + 1 ] = '\0';
		return index;
	}
}/* ~ namespace ssc*/
