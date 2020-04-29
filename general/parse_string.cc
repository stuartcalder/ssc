/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include <utility>

#include "parse_string.hh"

namespace ssc
{
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
}/* ~ namespace ssc*/
