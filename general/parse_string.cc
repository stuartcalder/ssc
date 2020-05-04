/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include <utility>
#include "parse_string.hh"
#include <ssc/general/error_conditions.hh>

namespace ssc
{
#if 0
	bool enforce_integer(std::string & str)
	{
		bool success = true;
		std::string s;
		for( char const ch : str )
			if( isdigit( static_cast<unsigned char>(ch) ) )
				s += ch;
		if( s.empty() )
			success = false;
		else
			str = std::move( s );
		return success;
	}/* ~ bool enforce_integer(std::string&) */
#else
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
#endif
}/* ~ namespace ssc*/
